package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/encondata/switchyard/internal/secrets"
	"github.com/encondata/switchyard/internal/totp"
)

// Roles (spec F7): admins manage everything including users and
// credentials; editors change hosts, folders and policies and apply;
// viewers only look.
var validRoles = map[string]bool{"admin": true, "editor": true, "viewer": true}

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{2,64}$`)

// MinPassword and MaxPassword bound passwords (bcrypt uses 72 bytes).
const (
	MinPassword = 8
	MaxPassword = 72
)

// CheckPassword returns a user-facing problem with a new password, or "".
func CheckPassword(pw string) string {
	switch {
	case len(pw) < MinPassword:
		return "at least 8 characters"
	case len(pw) > MaxPassword:
		return "at most 72 characters"
	case pw == DefaultAdminPassword:
		return "choose something other than the default password"
	}
	return ""
}

// ListUsers returns every user.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, role, must_change_password, disabled, totp_enabled, created_at
		FROM users ORDER BY username COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.MustChangePassword, &u.Disabled, &u.TOTPEnabled, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetUser returns one user.
func (s *Store) GetUser(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id, username, role, must_change_password, disabled, totp_enabled, created_at
		FROM users WHERE id = ?`, id).Scan(&u.ID, &u.Username, &u.Role, &u.MustChangePassword, &u.Disabled, &u.TOTPEnabled, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// CreateUser adds a user with a temporary password they must change.
func (s *Store) CreateUser(ctx context.Context, username, role, password, by string) (User, error) {
	username = strings.TrimSpace(username)
	errs := ValidationError{}
	if !usernameRE.MatchString(username) {
		errs["username"] = "2–64 letters, digits, dots, dashes, underscores or @"
	}
	if !validRoles[role] {
		errs["role"] = "choose admin, editor or viewer"
	}
	if msg := CheckPassword(password); msg != "" {
		errs["password"] = msg
	}
	if len(errs) > 0 {
		return User{}, errs
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, 1)`,
		username, string(hash), role)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ValidationError{"username": "that username is taken"}
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	if err := audit(ctx, tx, by, "create", "user", id, nil, map[string]string{"username": username, "role": role}); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// countActiveAdmins counts enabled admins other than exceptID.
func countActiveAdmins(ctx context.Context, tx *sql.Tx, exceptID int64) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?`, exceptID).Scan(&n)
	return n, err
}

// UpdateUser changes a user's role and disabled flag. There must always be
// at least one enabled admin.
func (s *Store) UpdateUser(ctx context.Context, id int64, role string, disabled bool, by string) (User, error) {
	if !validRoles[role] {
		return User{}, ValidationError{"role": "choose admin, editor or viewer"}
	}
	before, err := s.GetUser(ctx, id)
	if err != nil {
		return User{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if before.Role == "admin" && !before.Disabled && (role != "admin" || disabled) {
		if n, err := countActiveAdmins(ctx, tx, id); err != nil {
			return User{}, err
		} else if n == 0 {
			return User{}, ConflictError("This is the last admin. Make someone else an admin first.")
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		role, disabled, id); err != nil {
		return User{}, err
	}
	if disabled {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return User{}, err
		}
	}
	if err := audit(ctx, tx, by, "update", "user", id,
		map[string]any{"role": before.Role, "disabled": before.Disabled},
		map[string]any{"role": role, "disabled": disabled}); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// ResetPassword sets a temporary password the user must change, and signs
// them out everywhere.
func (s *Store) ResetPassword(ctx context.Context, id int64, password, by string) error {
	if msg := CheckPassword(password); msg != "" {
		return ValidationError{"password": msg}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, must_change_password = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		string(hash), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, by, "reset_password", "user", id, nil, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteUser removes a user (never the last admin).
func (s *Store) DeleteUser(ctx context.Context, id int64, by string) error {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if u.Role == "admin" && !u.Disabled {
		if n, err := countActiveAdmins(ctx, tx, id); err != nil {
			return err
		} else if n == 0 {
			return ConflictError("This is the last admin, so it can't be deleted.")
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, by, "delete", "user", id, map[string]string{"username": u.Username, "role": u.Role}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// --- settings ---

// SettingRequire2FA ("true" or "false") makes two-factor sign-in mandatory.
const SettingRequire2FA = "require_2fa"

// GetSetting returns a setting's value, or "" if unset.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a setting and audits the change.
func (s *Store) SetSetting(ctx context.Context, key, value, by string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
		return err
	}
	if err := audit(ctx, tx, by, "update", "setting", 0, nil, map[string]string{key: value}); err != nil {
		return err
	}
	return tx.Commit()
}

// --- two-factor sign-in ---

// BeginTOTP creates a new (not yet active) TOTP secret for a user and
// returns it. It replaces any unconfirmed secret.
func (s *Store) BeginTOTP(ctx context.Context, userID int64, box *secrets.Box) (string, error) {
	if !box.Ready() {
		return "", ConflictError("Two-factor sign-in needs CPM_SECRET_KEY to be set, so secrets can be stored encrypted.")
	}
	var enabled bool
	if err := s.db.QueryRowContext(ctx, `SELECT totp_enabled FROM users WHERE id = ?`, userID).Scan(&enabled); err != nil {
		return "", err
	}
	if enabled {
		return "", ConflictError("Two-factor sign-in is already on. Turn it off first to set it up again.")
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return "", err
	}
	sealed, err := box.Seal(secret, fmt.Sprintf("totp:%d", userID))
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE users SET totp_secret = ?, totp_last_step = 0 WHERE id = ?`, sealed, userID)
	return secret, err
}

// ConfirmTOTP turns two-factor sign-in on once the user proves their app
// works, and returns ten single-use backup codes (shown once).
func (s *Store) ConfirmTOTP(ctx context.Context, userID int64, code string, box *secrets.Box, by string) ([]string, error) {
	secret, lastStep, err := s.totpSecret(ctx, userID, box)
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, ConflictError("Start two-factor setup first.")
	}
	step, ok := totp.Verify(secret, code, time.Now(), lastStep)
	if !ok {
		return nil, ValidationError{"code": "that code doesn't match; check the time on your phone and try the next code"}
	}
	codes, hashes, err := newBackupCodes()
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_enabled = 1, totp_last_step = ?, backup_codes = ? WHERE id = ?`,
		step, hashes, userID); err != nil {
		return nil, err
	}
	if err := audit(ctx, tx, by, "enable_2fa", "user", userID, nil, nil); err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

// DisableTOTP turns two-factor sign-in off for a user.
func (s *Store) DisableTOTP(ctx context.Context, userID int64, by string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE users SET totp_enabled = 0, totp_secret = '', totp_last_step = 0, backup_codes = '[]' WHERE id = ?`, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := audit(ctx, tx, by, "disable_2fa", "user", userID, nil, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// VerifySecondFactor checks a TOTP code or an unused backup code.
func (s *Store) VerifySecondFactor(ctx context.Context, userID int64, code string, box *secrets.Box) error {
	secret, lastStep, err := s.totpSecret(ctx, userID, box)
	if err != nil {
		return err
	}
	if step, ok := totp.Verify(secret, code, time.Now(), lastStep); ok {
		// Claim the step atomically: a parallel request with the same code
		// finds it already used.
		res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, userID, step)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrBadCredentials
		}
		return nil
	}
	// Backup code: compare against each stored hash; remove the one used.
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT backup_codes FROM users WHERE id = ?`, userID).Scan(&raw); err != nil {
		return err
	}
	var hashes []string
	_ = json.Unmarshal([]byte(raw), &hashes)
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	for i, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(normalized)) == nil {
			rest := append(append([]string{}, hashes[:i]...), hashes[i+1:]...)
			b, _ := json.Marshal(rest)
			// Only succeeds if nobody used a code since we read the list.
			res, err := s.db.ExecContext(ctx, `UPDATE users SET backup_codes = ? WHERE id = ? AND backup_codes = ?`, string(b), userID, raw)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return ErrBadCredentials
			}
			return nil
		}
	}
	return ErrBadCredentials
}

func (s *Store) totpSecret(ctx context.Context, userID int64, box *secrets.Box) (string, int64, error) {
	var sealed string
	var last int64
	err := s.db.QueryRowContext(ctx, `SELECT totp_secret, totp_last_step FROM users WHERE id = ?`, userID).Scan(&sealed, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	if err != nil || sealed == "" {
		return "", last, err
	}
	secret, err := box.Open(sealed, fmt.Sprintf("totp:%d", userID))
	return secret, last, err
}

// BackupCodesLeft returns how many unused backup codes a user has.
func (s *Store) BackupCodesLeft(ctx context.Context, userID int64) (int, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT backup_codes FROM users WHERE id = ?`, userID).Scan(&raw); err != nil {
		return 0, err
	}
	var hashes []string
	_ = json.Unmarshal([]byte(raw), &hashes)
	return len(hashes), nil
}

func newBackupCodes() ([]string, string, error) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		b := make([]byte, 10)
		for j := range b {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return nil, "", err
			}
			b[j] = alphabet[n.Int64()]
		}
		codes[i] = string(b[:5]) + "-" + string(b[5:])
		h, err := bcrypt.GenerateFromPassword(b, bcrypt.MinCost+4)
		if err != nil {
			return nil, "", err
		}
		hashes[i] = string(h)
	}
	j, _ := json.Marshal(hashes)
	return codes, string(j), nil
}

// --- sign-in challenges (password OK, waiting for the second factor) ---

// CreateChallenge starts a 5-minute second-factor challenge.
func (s *Store) CreateChallenge(ctx context.Context, userID int64) (string, error) {
	tok, err := randomToken()
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO login_challenges (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		hashToken(tok), userID, time.Now().UTC().Add(5*time.Minute))
	return tok, err
}

// ChallengeUser returns the user waiting on a challenge, counting the
// attempt; after 5 attempts the challenge is gone.
func (s *Store) ChallengeUser(ctx context.Context, token string) (User, error) {
	h := hashToken(token)
	// Count the attempt and check the limit in one statement.
	var id int64
	err := s.db.QueryRowContext(ctx, `UPDATE login_challenges SET attempts = attempts + 1
		WHERE token_hash = ? AND attempts < 5 AND expires_at > ? RETURNING user_id`,
		h, time.Now().UTC()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM login_challenges WHERE token_hash = ?`, h)
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// DeleteChallenge ends a challenge (after success).
func (s *Store) DeleteChallenge(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_challenges WHERE token_hash = ? OR expires_at <= ?`,
		hashToken(token), time.Now().UTC())
	return err
}

// --- audit log ---

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Username string    `json:"username"`
	Action   string    `json:"action"`
	Entity   string    `json:"entity"`
	EntityID string    `json:"entity_id"`
	Before   string    `json:"before"`
	After    string    `json:"after"`
}

// ListAudit returns audit entries newest first, optionally only before an
// ID (paging) and for one entity type or user.
func (s *Store) ListAudit(ctx context.Context, beforeID int64, entity, username string, limit int) ([]AuditEntry, error) {
	q := `SELECT id, at, username, action, entity, entity_id, before, after FROM audit_log WHERE 1 = 1`
	var args []any
	if beforeID > 0 {
		q += ` AND id < ?`
		args = append(args, beforeID)
	}
	if entity != "" {
		q += ` AND entity = ?`
		args = append(args, entity)
	}
	if username != "" {
		q += ` AND username = ?`
		args = append(args, username)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Username, &e.Action, &e.Entity, &e.EntityID, &e.Before, &e.After); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditEvent records an event that isn't a data change (sign-ins, etc.).
func (s *Store) AuditEvent(ctx context.Context, username, action, entity string, id int64, details any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := audit(ctx, tx, username, action, entity, id, nil, details); err != nil {
		return err
	}
	return tx.Commit()
}
