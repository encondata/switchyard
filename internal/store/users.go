package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Default account created when the database has no users. The password must
// be changed at first sign-in.
const (
	DefaultAdminUsername = "admin"
	DefaultAdminPassword = "123456"
)

// ErrNotFound is returned when a user or session doesn't exist.
var ErrNotFound = errors.New("not found")

// ErrBadCredentials is returned for a wrong username or password.
var ErrBadCredentials = errors.New("invalid username or password")

// User is a CPM account.
type User struct {
	ID                 int64  `json:"id"`
	Username           string `json:"username"`
	Role               string `json:"role"`
	MustChangePassword bool   `json:"must_change_password"`
	Disabled           bool   `json:"disabled"`
	TOTPEnabled        bool   `json:"totp_enabled"`
	// MustEnroll2FA is set by the server when two-factor sign-in is
	// required and this user hasn't set it up yet.
	MustEnroll2FA bool      `json:"must_enroll_2fa"`
	CreatedAt     time.Time `json:"created_at,omitempty"`
}

// dummyHash is compared against when a username doesn't exist, so a login
// takes the same time whether or not the user exists.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("cpm-dummy-password"), bcrypt.DefaultCost)

// EnsureDefaultAdmin creates admin/123456 (must change password) if there
// are no users yet. It reports whether it created the account.
func (s *Store) EnsureDefaultAdmin(ctx context.Context) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(DefaultAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, 'admin', 1)`,
		DefaultAdminUsername, string(hash))
	return err == nil, err
}

// Authenticate checks a username and password.
func (s *Store) Authenticate(ctx context.Context, username, password string) (User, error) {
	var u User
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, role, must_change_password, disabled, totp_enabled, password_hash FROM users WHERE username = ?`,
		username).Scan(&u.ID, &u.Username, &u.Role, &u.MustChangePassword, &u.Disabled, &u.TOTPEnabled, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return User{}, ErrBadCredentials
	}
	if err != nil {
		return User{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || u.Disabled {
		return User{}, ErrBadCredentials
	}
	return u, nil
}

// ChangePassword checks the current password, sets the new one, clears the
// must-change flag and signs out the user's other sessions.
func (s *Store) ChangePassword(ctx context.Context, userID int64, current, next, keepToken string) error {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(current)) != nil {
		return ErrBadCredentials
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		string(newHash), userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, userID, hashToken(keepToken)); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSession starts a session for the user and returns its token.
func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		hashToken(token), userID, time.Now().UTC().Add(ttl))
	if err != nil {
		return "", err
	}
	return token, nil
}

// SessionUser returns the user for a valid, unexpired session token.
func (s *Store) SessionUser(ctx context.Context, token string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.must_change_password, u.totp_enabled
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0`,
		hashToken(token), time.Now().UTC()).Scan(&u.ID, &u.Username, &u.Role, &u.MustChangePassword, &u.TOTPEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

// DeleteExpiredSessions removes sessions past their expiry.
func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().UTC())
	return err
}

// ClearSessions signs everyone out (used after restoring a backup, whose
// sessions may have been revoked since it was taken).
func (s *Store) ClearSessions(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_challenges`)
	return err
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
