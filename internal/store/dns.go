package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/encondata/caddyproxymanager/internal/secrets"
)

// DNSProvider holds credentials for DNS-01 challenges (spec F2, CPM-15).
// The token itself is never returned by the API.
type DNSProvider struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"` // cloudflare
	TokenSet    bool      `json:"token_set"`
	HostCount   int       `json:"host_count"`
	FolderCount int       `json:"folder_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Cloudflare API tokens are 40 URL-safe characters; allow a little slack.
var cfTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{30,80}$`)

func purpose(id int64) string { return "dns-provider:" + strconv.FormatInt(id, 10) }

// ListDNSProviders returns providers with usage counts.
func (s *Store) ListDNSProviders(ctx context.Context) ([]DNSProvider, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.name, p.type, p.credentials != '', p.created_at, p.updated_at,
			(SELECT COUNT(*) FROM hosts h WHERE h.dns_provider_id = p.id),
			(SELECT COUNT(*) FROM folders f WHERE f.dns_provider_id = p.id)
		FROM dns_providers p ORDER BY p.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []DNSProvider{}
	for rows.Next() {
		var p DNSProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &p.TokenSet, &p.CreatedAt, &p.UpdatedAt, &p.HostCount, &p.FolderCount); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetDNSProvider returns one provider (without its token).
func (s *Store) GetDNSProvider(ctx context.Context, id int64) (DNSProvider, error) {
	all, err := s.ListDNSProviders(ctx)
	if err != nil {
		return DNSProvider{}, err
	}
	for _, p := range all {
		if p.ID == id {
			return p, nil
		}
	}
	return DNSProvider{}, ErrNotFound
}

// SaveDNSProvider creates (ID 0) or updates a provider. An empty token on
// update keeps the stored one.
func (s *Store) SaveDNSProvider(ctx context.Context, p DNSProvider, token string, box *secrets.Box, username string) (DNSProvider, error) {
	if !box.Ready() {
		return DNSProvider{}, ConflictError(secrets.ErrNoKey.Error())
	}
	p.Name = strings.TrimSpace(p.Name)
	token = strings.TrimSpace(token)
	if p.Type == "" {
		p.Type = "cloudflare"
	}
	errs := ValidationError{}
	if p.Name == "" {
		errs["name"] = "enter a name"
	} else if len(p.Name) > 100 {
		errs["name"] = "keep the name under 100 characters"
	}
	if p.Type != "cloudflare" {
		errs["type"] = "only Cloudflare is supported"
	}
	if p.ID == 0 && token == "" {
		errs["api_token"] = "paste the Cloudflare API token"
	} else if token != "" && !cfTokenRE.MatchString(token) {
		errs["api_token"] = "that doesn't look like a Cloudflare API token (40 letters, digits, - or _)"
	}
	if len(errs) > 0 {
		return DNSProvider{}, errs
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DNSProvider{}, err
	}
	defer func() { _ = tx.Rollback() }()
	action := "update"
	if p.ID == 0 {
		action = "create"
		res, err := tx.ExecContext(ctx, `INSERT INTO dns_providers (name, type, credentials) VALUES (?, ?, '')`, p.Name, p.Type)
		if err != nil {
			return DNSProvider{}, dnsNameError(err)
		}
		if p.ID, err = res.LastInsertId(); err != nil {
			return DNSProvider{}, err
		}
	} else {
		res, err := tx.ExecContext(ctx, `UPDATE dns_providers SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, p.Name, p.ID)
		if err != nil {
			return DNSProvider{}, dnsNameError(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return DNSProvider{}, ErrNotFound
		}
	}
	if token != "" {
		sealed, err := box.Seal(token, purpose(p.ID))
		if err != nil {
			return DNSProvider{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE dns_providers SET credentials = ? WHERE id = ?`, sealed, p.ID); err != nil {
			return DNSProvider{}, err
		}
	}
	// The audit entry records that the token changed, never the token.
	if err := audit(ctx, tx, username, action, "dns_provider", p.ID, nil,
		map[string]any{"name": p.Name, "type": p.Type, "token_changed": token != ""}); err != nil {
		return DNSProvider{}, err
	}
	if err := tx.Commit(); err != nil {
		return DNSProvider{}, err
	}
	return s.GetDNSProvider(ctx, p.ID)
}

func dnsNameError(err error) error {
	if strings.Contains(err.Error(), "UNIQUE") {
		return ValidationError{"name": "a provider with this name already exists"}
	}
	return err
}

// DeleteDNSProvider removes a provider that no host or folder uses.
func (s *Store) DeleteDNSProvider(ctx context.Context, id int64, username string) error {
	p, err := s.GetDNSProvider(ctx, id)
	if err != nil {
		return err
	}
	if p.HostCount > 0 || p.FolderCount > 0 {
		return ConflictError(fmt.Sprintf("“%s” is used by %d host(s) and %d folder(s). Change them first.", p.Name, p.HostCount, p.FolderCount))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns_providers WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, username, "delete", "dns_provider", id, map[string]string{"name": p.Name}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// DNSToken decrypts one provider's token.
func (s *Store) DNSToken(ctx context.Context, id int64, box *secrets.Box) (string, error) {
	var sealed string
	err := s.db.QueryRowContext(ctx, `SELECT credentials FROM dns_providers WHERE id = ?`, id).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return box.Open(sealed, purpose(id))
}

// DNSTokens decrypts every provider's token, keyed by provider ID.
func (s *Store) DNSTokens(ctx context.Context, box *secrets.Box) (map[int64]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, credentials FROM dns_providers`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var sealed string
		if err := rows.Scan(&id, &sealed); err != nil {
			return nil, err
		}
		tok, err := box.Open(sealed, purpose(id))
		if err != nil {
			return nil, fmt.Errorf("DNS provider %d: %w", id, err)
		}
		out[id] = tok
	}
	return out, rows.Err()
}
