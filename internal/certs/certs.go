// Package certs reads certificate status from Caddy's storage folder, which
// CPM mounts read-only (spec F2). Caddy events arrive in a later card; this
// scan is the backup source the spec calls for.
package certs

import (
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cert is one certificate Caddy holds.
type Cert struct {
	Names     []string  `json:"names"`
	Issuer    string    `json:"issuer"` // CA common name, e.g. "R11" or "Caddy Local Authority"
	Source    string    `json:"source"` // Caddy's issuer folder, e.g. "acme-v02.api.letsencrypt.org-directory" or "local"
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// Scan reads every certificate under <dataDir>/caddy/certificates. A missing
// folder is not an error (Caddy hasn't issued anything yet).
func Scan(dataDir string) ([]Cert, error) {
	root := filepath.Join(dataDir, "caddy", "certificates")
	var out []Cert
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return filepath.SkipDir
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".crt") {
			return nil
		}
		raw, err := os.ReadFile(path) //nolint:gosec // path comes from walking Caddy's own storage
		if err != nil {
			return nil // skip unreadable files rather than failing the page
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		source := strings.SplitN(rel, string(filepath.Separator), 2)[0]
		names := c.DNSNames
		if len(names) == 0 && c.Subject.CommonName != "" {
			names = []string{c.Subject.CommonName}
		}
		out = append(out, Cert{
			Names: names, Issuer: c.Issuer.CommonName, Source: source,
			NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return out, nil
}

// Status of one domain's certificate.
type Status struct {
	Domain   string     `json:"domain"`
	State    string     `json:"state"` // valid | expiring | expired | pending | not_needed
	Issuer   string     `json:"issuer,omitempty"`
	Source   string     `json:"source,omitempty"`
	NotAfter *time.Time `json:"not_after,omitempty"`
}

// ExpiringWithin is when a cert counts as expiring (spec F2: 14 days).
// A cert only counts once Caddy's own renewal point (a third of its lifetime
// left) has passed, so short-lived certs that Caddy renews on schedule, like
// the 12-hour internal ones, don't raise false alarms.
const ExpiringWithin = 14 * 24 * time.Hour

// For returns the status of a domain, picking the cert that expires last.
// Wildcard certs cover one label (*.example.com covers a.example.com).
func For(domain string, all []Cert, now time.Time) Status {
	st := Status{Domain: domain, State: "pending"}
	var best *Cert
	for i := range all {
		c := &all[i]
		if covers(c.Names, domain) && (best == nil || c.NotAfter.After(best.NotAfter)) {
			best = c
		}
	}
	if best == nil {
		return st
	}
	na := best.NotAfter
	st.Issuer, st.Source, st.NotAfter = best.Issuer, best.Source, &na
	switch {
	case now.After(na):
		st.State = "expired"
	case na.Sub(now) < ExpiringWithin && na.Sub(now) < best.NotAfter.Sub(best.NotBefore)/3:
		st.State = "expiring"
	default:
		st.State = "valid"
	}
	return st
}

func covers(names []string, domain string) bool {
	for _, n := range names {
		n = strings.ToLower(n)
		if n == domain {
			return true
		}
		if strings.HasPrefix(n, "*.") && !strings.HasPrefix(domain, "*.") {
			if i := strings.IndexByte(domain, '.'); i > 0 && domain[i+1:] == n[2:] {
				return true
			}
		}
	}
	return false
}
