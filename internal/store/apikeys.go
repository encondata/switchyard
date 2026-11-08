package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

// APIKeyPrefix starts every API key, so keys are easy to recognise (and to
// find with secret scanners) if one leaks.
const APIKeyPrefix = "sy_"

// APIKey is a key another program uses to call the API. Permissions are
// operation IDs (e.g. "hosts.update"); the server checks each request
// against them.
type APIKey struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"` // first characters, to tell keys apart
	Permissions []string   `json:"permissions"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	LastUsedIP  string     `json:"last_used_ip"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

// Active reports whether the key can still be used.
func (k APIKey) Active(now time.Time) bool {
	return k.RevokedAt == nil && (k.ExpiresAt == nil || now.Before(*k.ExpiresAt))
}

// Allows reports whether the key may call operation op.
func (k APIKey) Allows(op string) bool {
	for _, p := range k.Permissions {
		if p == op {
			return true
		}
	}
	return false
}

func cleanPermissions(perms []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range perms {
		p = strings.TrimSpace(p)
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func validateKey(name string, perms []string) (string, ValidationError) {
	name = strings.TrimSpace(name)
	errs := ValidationError{}
	switch {
	case name == "":
		errs["name"] = "Give the key a name, such as the program that will use it."
	case len(name) > 100:
		errs["name"] = "Keep the name under 100 characters."
	}
	if len(perms) == 0 {
		errs["permissions"] = "Choose at least one thing this key may do."
	}
	return name, errs
}

// CreateAPIKey makes a key and returns it with its token. The token is not
// stored and can't be shown again.
func (s *Store) CreateAPIKey(ctx context.Context, name string, perms []string, expires *time.Time, by string) (APIKey, string, error) {
	perms = cleanPermissions(perms)
	name, errs := validateKey(name, perms)
	if expires != nil && !expires.After(time.Now()) {
		errs["expires_at"] = "The expiry date must be in the future."
	}
	if len(errs) > 0 {
		return APIKey{}, "", errs
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return APIKey{}, "", err
	}
	token := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(b)
	pj, _ := json.Marshal(perms)
	var exp any
	if expires != nil {
		exp = expires.UTC()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO api_keys (name, prefix, token_hash, permissions, created_by, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, name, token[:len(APIKeyPrefix)+6], hashToken(token), string(pj), by, exp)
	if err != nil {
		return APIKey{}, "", err
	}
	id, _ := res.LastInsertId()
	k, err := s.GetAPIKey(ctx, id)
	if err != nil {
		return k, "", err
	}
	_ = s.AuditEvent(ctx, by, "create", "api_key", id, map[string]any{"name": name, "permissions": perms})
	return k, token, nil
}

const apiKeyCols = `id, name, prefix, permissions, created_by, created_at, updated_at, expires_at, last_used_at, last_used_ip, revoked_at`

func scanAPIKey(sc interface{ Scan(...any) error }) (APIKey, error) {
	var k APIKey
	var perms string
	var exp, used, revoked sql.NullTime
	if err := sc.Scan(&k.ID, &k.Name, &k.Prefix, &perms, &k.CreatedBy, &k.CreatedAt, &k.UpdatedAt, &exp, &used, &k.LastUsedIP, &revoked); err != nil {
		return k, err
	}
	_ = json.Unmarshal([]byte(perms), &k.Permissions)
	if k.Permissions == nil {
		k.Permissions = []string{}
	}
	for _, p := range []struct {
		src sql.NullTime
		dst **time.Time
	}{{exp, &k.ExpiresAt}, {used, &k.LastUsedAt}, {revoked, &k.RevokedAt}} {
		if p.src.Valid {
			t := p.src.Time.UTC()
			*p.dst = &t
		}
	}
	return k, nil
}

// GetAPIKey returns one key (without its token).
func (s *Store) GetAPIKey(ctx context.Context, id int64) (APIKey, error) {
	k, err := scanAPIKey(s.db.QueryRowContext(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return k, ErrNotFound
	}
	return k, err
}

// ListAPIKeys returns every key, newest first, revoked ones included.
func (s *Store) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+apiKeyCols+` FROM api_keys ORDER BY revoked_at IS NOT NULL, id DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// UpdateAPIKey renames a key and replaces its permissions and expiry. The
// token stays the same, so the program using it carries on.
func (s *Store) UpdateAPIKey(ctx context.Context, id int64, name string, perms []string, expires *time.Time, by string) (APIKey, error) {
	perms = cleanPermissions(perms)
	name, errs := validateKey(name, perms)
	if len(errs) > 0 {
		return APIKey{}, errs
	}
	cur, err := s.GetAPIKey(ctx, id)
	if err != nil {
		return cur, err
	}
	if cur.RevokedAt != nil {
		return cur, ConflictError("This key has been revoked. Make a new one instead.")
	}
	pj, _ := json.Marshal(perms)
	var exp any
	if expires != nil {
		exp = expires.UTC()
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE api_keys SET name = ?, permissions = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, name, string(pj), exp, id); err != nil {
		return cur, err
	}
	_ = s.AuditEvent(ctx, by, "update", "api_key", id, map[string]any{
		"name": name, "permissions": perms, "before": map[string]any{"name": cur.Name, "permissions": cur.Permissions},
	})
	return s.GetAPIKey(ctx, id)
}

// RevokeAPIKey stops a key working at once. The record stays, for the audit
// trail.
func (s *Store) RevokeAPIKey(ctx context.Context, id int64, by string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.GetAPIKey(ctx, id); err != nil {
			return err
		}
		return nil // already revoked
	}
	return s.AuditEvent(ctx, by, "revoke", "api_key", id, nil)
}

// APIKeyByToken finds the active key with this token. Unknown, revoked and
// expired keys are all ErrNotFound.
func (s *Store) APIKeyByToken(ctx context.Context, token string) (APIKey, error) {
	if !strings.HasPrefix(token, APIKeyPrefix) {
		return APIKey{}, ErrNotFound
	}
	k, err := scanAPIKey(s.db.QueryRowContext(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE token_hash = ?`, hashToken(token)))
	if errors.Is(err, sql.ErrNoRows) {
		return k, ErrNotFound
	}
	if err != nil {
		return k, err
	}
	if !k.Active(time.Now()) {
		return k, ErrNotFound
	}
	return k, nil
}

// TouchAPIKey records that a key was just used, at most once a minute.
func (s *Store) TouchAPIKey(ctx context.Context, id int64, ip string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP, last_used_ip = ?
		WHERE id = ? AND (last_used_at IS NULL OR last_used_at < datetime('now', '-1 minute'))`, ip, id)
	return err
}
