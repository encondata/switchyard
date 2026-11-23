package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Where an account or a session came from.
const (
	AuthLocal = "local"
	AuthOIDC  = "oidc"
)

// oidcPasswordMarker is stored as the password hash of HackSpaceLabs accounts. It is not a bcrypt hash,
// so no password can ever match it.
const oidcPasswordMarker = "!hackspacelabs"

// Errors from OIDCUser. The server turns them into the sign-in page's error codes.
var (
	// ErrAccountExists: the username belongs to another account (a local one, or a HackSpaceLabs
	// account for a different Keycloak user). There is no linking in Switchyard.
	ErrAccountExists = errors.New("an account with that username already exists")
	// ErrUsernameInvalid: the Keycloak username doesn't fit Switchyard's username rule.
	ErrUsernameInvalid = errors.New("username not allowed")
	// ErrAccountDisabled: the account exists but an admin disabled it.
	ErrAccountDisabled = errors.New("account disabled")
)

// Session is what a session token says beyond its user.
type Session struct {
	AuthSource   string
	IDPSessionID string
	// IDPTokens are Keycloak's refresh and ID tokens, sealed with CPM_SECRET_KEY.
	IDPTokens    string
	IDPCheckedAt time.Time
	ExpiresAt    time.Time
}

// SessionInfo returns the user and session for a valid, unexpired session token.
func (s *Store) SessionInfo(ctx context.Context, token string) (User, Session, error) {
	var u User
	var ss Session
	var checked sql.NullTime
	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.must_change_password, u.totp_enabled, u.auth_source, u.display_name, u.email,
		       s.auth_source, s.idp_sid, s.idp_tokens, s.idp_checked_at, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0`,
		hashToken(token), time.Now().UTC()).Scan(&u.ID, &u.Username, &u.Role, &u.MustChangePassword, &u.TOTPEnabled,
		&u.AuthSource, &u.DisplayName, &u.Email,
		&ss.AuthSource, &ss.IDPSessionID, &ss.IDPTokens, &checked, &ss.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, Session{}, ErrNotFound
	}
	if checked.Valid {
		ss.IDPCheckedAt = checked.Time
	}
	return u, ss, err
}

// CreateOIDCSession starts a session for a HackSpaceLabs sign-in and returns its token.
func (s *Store) CreateOIDCSession(ctx context.Context, userID int64, ttl time.Duration, idpSID, sealedTokens string) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at, auth_source, idp_sid, idp_tokens, idp_checked_at)
		VALUES (?, ?, ?, 'oidc', ?, ?, ?)`, hashToken(token), userID, now.Add(ttl), idpSID, sealedTokens, now)
	if err != nil {
		return "", err
	}
	return token, nil
}

// RenewOIDCSession records a successful recheck: new tokens, and an expiry that follows Keycloak's.
func (s *Store) RenewOIDCSession(ctx context.Context, token string, ttl time.Duration, sealedTokens string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET idp_tokens = ?, idp_checked_at = ?, expires_at = ?
		WHERE token_hash = ? AND auth_source = 'oidc'`, sealedTokens, now, now.Add(ttl), hashToken(token))
	return err
}

// MarkOIDCChecked records a recheck attempt that couldn't reach Keycloak, so the next one waits.
func (s *Store) MarkOIDCChecked(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET idp_checked_at = ? WHERE token_hash = ?`, time.Now().UTC(), hashToken(token))
	return err
}

// SaveOIDCFlow keeps a sign-in in progress for ten minutes.
func (s *Store) SaveOIDCFlow(ctx context.Context, state, nonce, verifier, next string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_flows (state_hash, nonce, verifier, next_path, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hashToken(state), nonce, verifier, next, time.Now().UTC().Add(10*time.Minute))
	return err
}

// TakeOIDCFlow returns a sign-in in progress and deletes it, so a callback works once.
func (s *Store) TakeOIDCFlow(ctx context.Context, state string) (nonce, verifier, next string, err error) {
	err = s.db.QueryRowContext(ctx, `DELETE FROM oidc_flows WHERE state_hash = ? AND expires_at > ?
		RETURNING nonce, verifier, next_path`, hashToken(state), time.Now().UTC()).Scan(&nonce, &verifier, &next)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return nonce, verifier, next, err
}

// OIDCUser finds or creates the account for a HackSpaceLabs sign-in, keyed by the Keycloak user id
// (subject), and sets its role and profile. by is the name the audit log records.
//
// Errors: ErrAccountExists, ErrUsernameInvalid, ErrAccountDisabled, or a ConflictError when the new
// role would leave Switchyard without an enabled admin.
func (s *Store) OIDCUser(ctx context.Context, subject, username, displayName, email, role string) (User, error) {
	if subject == "" || !validRoles[role] {
		return User{}, errors.New("subject and a valid role are required")
	}
	username = strings.TrimSpace(username)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	var currentRole, currentName string
	var disabled bool
	err = tx.QueryRowContext(ctx, `SELECT id, role, username, disabled FROM users WHERE oidc_subject = ?`, subject).
		Scan(&id, &currentRole, &currentName, &disabled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if !usernameRE.MatchString(username) {
			return User{}, ErrUsernameInvalid
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE username = ? COLLATE NOCASE`, username).Scan(&n); err != nil {
			return User{}, err
		}
		if n > 0 {
			return User{}, ErrAccountExists
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO users (username, password_hash, role, must_change_password, auth_source,
			oidc_subject, display_name, email) VALUES (?, ?, ?, 0, 'oidc', ?, ?, ?)`,
			username, oidcPasswordMarker, role, subject, displayName, email)
		if err != nil {
			return User{}, err
		}
		id, _ = res.LastInsertId()
		if err := audit(ctx, tx, username, "create", "user", id, nil,
			map[string]string{"username": username, "role": role, "sign_in": "hackspacelabs"}); err != nil {
			return User{}, err
		}
	case err != nil:
		return User{}, err
	default:
		if disabled {
			return User{}, ErrAccountDisabled
		}
		if currentRole != role {
			if err := s.setOIDCRole(ctx, tx, id, currentName, currentRole, role); err != nil {
				return User{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			displayName, email, id); err != nil {
			return User{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// SyncOIDCRole applies the role Keycloak now gives a HackSpaceLabs account (on a recheck).
func (s *Store) SyncOIDCRole(ctx context.Context, userID int64, role string) error {
	if !validRoles[role] {
		return errors.New("invalid role")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var current, name string
	if err := tx.QueryRowContext(ctx, `SELECT role, username FROM users WHERE id = ? AND auth_source = 'oidc'`, userID).
		Scan(&current, &name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if current == role {
		return nil
	}
	if err := s.setOIDCRole(ctx, tx, userID, name, current, role); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) setOIDCRole(ctx context.Context, tx *sql.Tx, id int64, name, from, to string) error {
	if from == "admin" && to != "admin" {
		if n, err := countActiveAdmins(ctx, tx, id); err != nil {
			return err
		} else if n == 0 {
			return ConflictError("This is the last admin; HackSpaceLabs no longer gives them the admin role.")
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, to, id); err != nil {
		return err
	}
	return audit(ctx, tx, "hackspacelabs", "update", "user", id,
		map[string]string{"username": name, "role": from}, map[string]string{"username": name, "role": to})
}

// LocalAccountsWithFirstPassword lists enabled local accounts that still have to change a temporary or
// well-known first password (logged as a warning when HackSpaceLabs sign-in is on).
func (s *Store) LocalAccountsWithFirstPassword(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username FROM users WHERE auth_source = 'local' AND must_change_password = 1 AND disabled = 0`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
