package store

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/encondata/caddyproxymanager/internal/secrets"
)

const cfToken = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-Ab"

func testBox(t *testing.T) *secrets.Box {
	t.Helper()
	b, err := secrets.New(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDNSProviders(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	box := testBox(t)

	var conflict ConflictError
	if _, err := s.SaveDNSProvider(ctx, DNSProvider{Name: "cf"}, cfToken, nil, "admin"); !errors.As(err, &conflict) {
		t.Fatalf("without key err = %v", err)
	}
	var verr ValidationError
	if _, err := s.SaveDNSProvider(ctx, DNSProvider{Name: "cf"}, `"quoted token"`, box, "admin"); !errors.As(err, &verr) || verr["api_token"] == "" {
		t.Fatalf("bad token err = %v", err)
	}

	p, err := s.SaveDNSProvider(ctx, DNSProvider{Name: "Cloudflare main"}, cfToken, box, "admin")
	if err != nil || !p.TokenSet || p.Type != "cloudflare" {
		t.Fatalf("save = %+v, %v", p, err)
	}
	// The token is stored sealed, never in plain text.
	var stored string
	_ = s.db.QueryRow(`SELECT credentials FROM dns_providers WHERE id = ?`, p.ID).Scan(&stored)
	if strings.Contains(stored, cfToken) || !strings.HasPrefix(stored, "v1:") {
		t.Fatalf("token stored in the clear: %q", stored)
	}
	var auditRows string
	_ = s.db.QueryRow(`SELECT group_concat(after) FROM audit_log WHERE entity = 'dns_provider'`).Scan(&auditRows)
	if strings.Contains(auditRows, cfToken) {
		t.Fatal("token written to the audit log")
	}
	if tok, err := s.DNSToken(ctx, p.ID, box); err != nil || tok != cfToken {
		t.Fatalf("DNSToken = %q, %v", tok, err)
	}

	// Renaming without a token keeps the stored token.
	p.Name = "CF"
	if _, err := s.SaveDNSProvider(ctx, p, "", box, "admin"); err != nil {
		t.Fatal(err)
	}
	if tok, _ := s.DNSToken(ctx, p.ID, box); tok != cfToken {
		t.Fatal("token lost on rename")
	}

	// DNS hosts need a provider: their own or a folder default.
	h := Host{Type: Host404, Enabled: true, Domains: []string{"*.lan.example.com"}, TLSMode: TLSDNS}
	if _, err := s.SaveHost(ctx, h, "admin"); !errors.As(err, &verr) || verr["dns_provider_id"] == "" {
		t.Fatalf("dns host without provider err = %v", err)
	}
	top, _ := s.SaveFolder(ctx, Folder{Name: "LAN", DNSProviderID: &p.ID}, "admin")
	sub, _ := s.SaveFolder(ctx, Folder{Name: "NAS", ParentID: &top.ID}, "admin")
	h.FolderID = &sub.ID
	saved, err := s.SaveHost(ctx, h, "admin")
	if err != nil || saved.TLSMode != TLSDNS {
		t.Fatalf("dns host via folder default = %+v, %v", saved, err)
	}
	st, _ := s.LoadAccessState(ctx)
	if id, ok := st.EffectiveDNSProvider(saved); !ok || id != p.ID {
		t.Fatalf("effective provider = %d, %v", id, ok)
	}

	if err := s.DeleteDNSProvider(ctx, p.ID, "admin"); !errors.As(err, &conflict) {
		t.Fatalf("delete used provider err = %v", err)
	}
	tokens, err := s.DNSTokens(ctx, box)
	if err != nil || tokens[p.ID] != cfToken {
		t.Fatalf("DNSTokens = %v, %v", tokens, err)
	}
}
