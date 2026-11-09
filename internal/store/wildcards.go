package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
)

// WildcardCert is a shared *.Domain certificate, obtained with the DNS
// challenge through DNSProviderID. Hosts it covers use it instead of a
// certificate of their own.
type WildcardCert struct {
	ID            int64     `json:"id"`
	Domain        string    `json:"domain"` // example.com (for *.example.com)
	DNSProviderID int64     `json:"dns_provider_id"`
	IncludeApex   bool      `json:"include_apex"` // also covers example.com itself
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Names are the names on the certificate.
func (w WildcardCert) Names() []string {
	n := []string{"*." + w.Domain}
	if w.IncludeApex {
		n = append(n, w.Domain)
	}
	return n
}

// Covers reports whether the certificate is valid for name: the wildcard
// itself, the bare domain (if included), or one label under it (a wildcard
// covers exactly one level: not a.b.example.com).
func (w WildcardCert) Covers(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	d := strings.ToLower(w.Domain)
	switch name {
	case d:
		return w.IncludeApex
	case "*." + d:
		return true
	}
	label, ok := strings.CutSuffix(name, "."+d)
	return ok && label != "" && label != "*" && !strings.Contains(label, ".")
}

// CoveringWildcard returns the wildcard certificate that covers name.
func CoveringWildcard(ws []WildcardCert, name string) (WildcardCert, bool) {
	for _, w := range ws {
		if w.Covers(name) {
			return w, true
		}
	}
	return WildcardCert{}, false
}

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// ListWildcards returns every wildcard certificate, by domain.
func (s *Store) ListWildcards(ctx context.Context) ([]WildcardCert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, domain, dns_provider_id, include_apex, created_at, updated_at
		FROM wildcard_certs ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []WildcardCert{}
	for rows.Next() {
		var w WildcardCert
		if err := rows.Scan(&w.ID, &w.Domain, &w.DNSProviderID, &w.IncludeApex, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// SaveWildcard creates (ID 0) or updates a wildcard certificate.
func (s *Store) SaveWildcard(ctx context.Context, w WildcardCert, username string) (WildcardCert, error) {
	w.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(w.Domain), "."))
	w.Domain = strings.TrimPrefix(w.Domain, "*.")
	errs := ValidationError{}
	if !domainRE.MatchString(w.Domain) {
		errs["domain"] = "a domain like example.com (the certificate is for *.example.com)"
	}
	if w.DNSProviderID == 0 {
		errs["dns_provider_id"] = "choose the DNS provider for this domain (wildcards need the DNS challenge)"
	} else if _, err := s.GetDNSProvider(ctx, w.DNSProviderID); errors.Is(err, ErrNotFound) {
		errs["dns_provider_id"] = "that DNS provider doesn't exist"
	} else if err != nil {
		return w, err
	}
	if len(errs) > 0 {
		return w, errs
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return w, err
	}
	defer func() { _ = tx.Rollback() }()
	var before any
	if w.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO wildcard_certs (domain, dns_provider_id, include_apex) VALUES (?, ?, ?)`,
			w.Domain, w.DNSProviderID, w.IncludeApex)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return w, ValidationError{"domain": "there's already a wildcard certificate for this domain"}
			}
			return w, err
		}
		w.ID, _ = res.LastInsertId()
	} else {
		cur, err := s.getWildcard(ctx, w.ID)
		if err != nil {
			return w, err
		}
		before = cur
		if _, err := tx.ExecContext(ctx, `UPDATE wildcard_certs SET domain = ?, dns_provider_id = ?, include_apex = ?,
			updated_at = CURRENT_TIMESTAMP WHERE id = ?`, w.Domain, w.DNSProviderID, w.IncludeApex, w.ID); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return w, ValidationError{"domain": "there's already a wildcard certificate for this domain"}
			}
			return w, err
		}
	}
	action := "create"
	if before != nil {
		action = "update"
	}
	if err := audit(ctx, tx, username, action, "wildcard", w.ID, before, w); err != nil {
		return w, err
	}
	if err := tx.Commit(); err != nil {
		return w, err
	}
	return s.getWildcard(ctx, w.ID)
}

func (s *Store) getWildcard(ctx context.Context, id int64) (WildcardCert, error) {
	var w WildcardCert
	err := s.db.QueryRowContext(ctx, `SELECT id, domain, dns_provider_id, include_apex, created_at, updated_at
		FROM wildcard_certs WHERE id = ?`, id).Scan(&w.ID, &w.Domain, &w.DNSProviderID, &w.IncludeApex, &w.CreatedAt, &w.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return w, ErrNotFound
	}
	return w, err
}

// DeleteWildcard removes a wildcard certificate; hosts it covered get their
// own certificates again at the next apply.
func (s *Store) DeleteWildcard(ctx context.Context, id int64, username string) error {
	cur, err := s.getWildcard(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM wildcard_certs WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, username, "delete", "wildcard", id, cur, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// wildcardsUsingProvider counts wildcard certificates on a DNS provider.
func (s *Store) wildcardsUsingProvider(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wildcard_certs WHERE dns_provider_id = ?`, id).Scan(&n)
	return n, err
}
