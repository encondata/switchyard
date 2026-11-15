package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/encondata/switchyard/internal/secrets"
)

// MailDomain is a domain whose mail is at Purelymail, with its DNS on a
// Cloudflare DNS provider.
type MailDomain struct {
	ID            int64      `json:"id"`
	Domain        string     `json:"domain"`
	DNSProviderID int64      `json:"dns_provider_id"`
	ZoneID        string     `json:"zone_id"`
	ZoneName      string     `json:"zone_name"`
	Status        string     `json:"status"` // ok, incomplete, conflict, error ('' = not checked)
	StatusDetail  string     `json:"status_detail,omitempty"`
	CheckedAt     *time.Time `json:"checked_at"`
	// PasswordSet says whether the shared account password is set (it's
	// only shown on request).
	PasswordSet bool      `json:"password_set"`
	Accounts    int       `json:"accounts"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const (
	settingPurelymailOwnership = "purelymail_ownership"
	settingPurelymailKey       = "purelymail_key"
	purelymailKeyPurpose       = "purelymail-api"
)

// NormalizeMailDomain lower-cases and checks a domain name.
func NormalizeMailDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	if !domainRE.MatchString(d) || len(d) > 253 {
		return "", ValidationError{"domain": "enter a domain name, e.g. example.com"}
	}
	return d, nil
}

const mailCols = `id, domain, dns_provider_id, zone_id, zone_name, status, status_detail, checked_at,
	password_sealed != '', (SELECT COUNT(*) FROM mail_accounts a WHERE a.mail_domain_id = mail_domains.id),
	created_at, updated_at`

func scanMail(sc interface{ Scan(...any) error }) (MailDomain, error) {
	var m MailDomain
	var checked sql.NullTime
	err := sc.Scan(&m.ID, &m.Domain, &m.DNSProviderID, &m.ZoneID, &m.ZoneName, &m.Status, &m.StatusDetail, &checked,
		&m.PasswordSet, &m.Accounts, &m.CreatedAt, &m.UpdatedAt)
	if checked.Valid {
		t := checked.Time
		m.CheckedAt = &t
	}
	return m, err
}

// ListMailDomains returns every mail domain, by name.
func (s *Store) ListMailDomains(ctx context.Context) ([]MailDomain, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+mailCols+` FROM mail_domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []MailDomain{}
	for rows.Next() {
		m, err := scanMail(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetMailDomain returns one mail domain.
func (s *Store) GetMailDomain(ctx context.Context, id int64) (MailDomain, error) {
	m, err := scanMail(s.db.QueryRowContext(ctx, `SELECT `+mailCols+` FROM mail_domains WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return MailDomain{}, ErrNotFound
	}
	return m, err
}

// CreateMailDomain adds a mail domain. The caller has found its zone.
func (s *Store) CreateMailDomain(ctx context.Context, m MailDomain, username string) (MailDomain, error) {
	d, err := NormalizeMailDomain(m.Domain)
	if err != nil {
		return MailDomain{}, err
	}
	m.Domain = d
	if _, err := s.GetDNSProvider(ctx, m.DNSProviderID); errors.Is(err, ErrNotFound) {
		return MailDomain{}, ValidationError{"dns_provider_id": "choose a DNS provider"}
	} else if err != nil {
		return MailDomain{}, err
	}
	if m.ZoneID == "" || m.ZoneName == "" {
		return MailDomain{}, errors.New("store: mail domain without a zone")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MailDomain{}, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO mail_domains (domain, dns_provider_id, zone_id, zone_name) VALUES (?, ?, ?, ?)`,
		m.Domain, m.DNSProviderID, m.ZoneID, m.ZoneName)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return MailDomain{}, ValidationError{"domain": "this domain is already on the list"}
		}
		return MailDomain{}, err
	}
	if m.ID, err = res.LastInsertId(); err != nil {
		return MailDomain{}, err
	}
	if err := audit(ctx, tx, username, "create", "mail_domain", m.ID, nil,
		map[string]any{"domain": m.Domain, "dns_provider_id": m.DNSProviderID, "zone": m.ZoneName}); err != nil {
		return MailDomain{}, err
	}
	if err := tx.Commit(); err != nil {
		return MailDomain{}, err
	}
	return s.GetMailDomain(ctx, m.ID)
}

// SetMailStatus records the result of checking a domain's records.
func (s *Store) SetMailStatus(ctx context.Context, id int64, status, detail string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mail_domains SET status = ?, status_detail = ?, checked_at = ? WHERE id = ?`,
		status, detail, at.UTC(), id)
	return err
}

// AuditMailRecords logs DNS records Switchyard added or deleted for a mail
// domain (deleted records in full, so they can be put back by hand).
func (s *Store) AuditMailRecords(ctx context.Context, id int64, username string, changes any) error {
	return s.AuditMail(ctx, id, username, "dns_records", changes)
}

// AuditMail logs an action on a mail domain (DNS records, Purelymail).
func (s *Store) AuditMail(ctx context.Context, id int64, username, action string, detail any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE mail_domains SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, username, action, "mail_domain", id, nil, detail); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteMailDomain takes a domain off the list. Its DNS records stay. A
// domain with email accounts can't go: their passwords would be lost.
func (s *Store) DeleteMailDomain(ctx context.Context, id int64, username string) error {
	m, err := s.GetMailDomain(ctx, id)
	if err != nil {
		return err
	}
	if m.Accounts > 0 {
		return ConflictError(fmt.Sprintf("%s has %d email account(s); delete them first", m.Domain, m.Accounts))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_domains WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, username, "delete", "mail_domain", id, map[string]string{"domain": m.Domain}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// mailDomainsUsingProvider counts mail domains on a DNS provider.
func (s *Store) mailDomainsUsingProvider(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_domains WHERE dns_provider_id = ?`, id).Scan(&n)
	return n, err
}

// PurelymailOwnership is the account's ownership proof (a TXT value from
// Purelymail's Add New Domain page; the same for every domain).
func (s *Store) PurelymailOwnership(ctx context.Context) (string, error) {
	return s.GetSetting(ctx, settingPurelymailOwnership)
}

// SavePurelymailOwnership stores the ownership proof ("" clears it).
func (s *Store) SavePurelymailOwnership(ctx context.Context, v, by string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	if len(v) > 255 || strings.ContainsAny(v, "\"\\") || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return "", ValidationError{"ownership": "paste the TXT value exactly as Purelymail shows it (one line, up to 255 characters)"}
	}
	// Not SetSetting: its "setting" audit entries count as pending Caddy
	// changes, and this isn't one.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, settingPurelymailOwnership, v); err != nil {
		return "", fmt.Errorf("saving ownership proof: %w", err)
	}
	if err := audit(ctx, tx, by, "update", "mail_settings", 0, nil, map[string]string{"ownership": v}); err != nil {
		return "", err
	}
	return v, tx.Commit()
}

// PurelymailKeySet reports whether an API key is stored.
func (s *Store) PurelymailKeySet(ctx context.Context) (bool, error) {
	v, err := s.GetSetting(ctx, settingPurelymailKey)
	return v != "", err
}

// PurelymailKey decrypts the Purelymail API key ("" if none).
func (s *Store) PurelymailKey(ctx context.Context, box *secrets.Box) (string, error) {
	sealed, err := s.GetSetting(ctx, settingPurelymailKey)
	if err != nil || sealed == "" {
		return "", err
	}
	return box.Open(sealed, purelymailKeyPurpose)
}

// CleanPurelymailKey trims a pasted API key and checks its shape.
func CleanPurelymailKey(k string) (string, error) {
	k = strings.Trim(strings.TrimSpace(k), `"'`)
	if len(k) < 10 || len(k) > 200 || strings.ContainsFunc(k, func(r rune) bool { return r <= 0x20 || r > 0x7e }) {
		return "", ValidationError{"api_key": "paste the API token from your Purelymail account (one line, no spaces)"}
	}
	return k, nil
}

// SavePurelymailKey seals and stores the API key ("" removes it). Like the
// ownership proof, it isn't Caddy config, so it's audited as mail_settings.
func (s *Store) SavePurelymailKey(ctx context.Context, key string, box *secrets.Box, by string) error {
	sealed := ""
	if key != "" {
		if !box.Ready() {
			return ConflictError(secrets.ErrNoKey.Error())
		}
		var err error
		if sealed, err = box.Seal(key, purelymailKeyPurpose); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, settingPurelymailKey, sealed); err != nil {
		return err
	}
	// The audit entry records that the key changed, never the key.
	if err := audit(ctx, tx, by, "update", "mail_settings", 0, nil, map[string]bool{"api_key_set": key != ""}); err != nil {
		return err
	}
	return tx.Commit()
}
