package store

import (
	"context"
	"errors"
	"testing"
)

func TestWildcardCovers(t *testing.T) {
	w := WildcardCert{Domain: "example.com", IncludeApex: true}
	for name, want := range map[string]bool{
		"app.example.com":   true,
		"APP.Example.com.":  true,
		"example.com":       true,
		"*.example.com":     true,
		"a.b.example.com":   false, // one level only
		"example.org":       false,
		"badexample.com":    false,
		"*.a.example.com":   false,
		"app.example.com.x": false,
	} {
		if got := w.Covers(name); got != want {
			t.Errorf("Covers(%q) = %v, want %v", name, got, want)
		}
	}
	w.IncludeApex = false
	if w.Covers("example.com") {
		t.Error("apex covered without IncludeApex")
	}
	if n := w.Names(); len(n) != 1 || n[0] != "*.example.com" {
		t.Errorf("Names = %v", n)
	}
}

func TestSaveWildcard(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	box := testBox(t)
	p, err := s.SaveDNSProvider(ctx, DNSProvider{Name: "CF", Type: "cloudflare"}, "abcdefghijklmnopqrstuvwxyz0123456789ABCD", box, "admin")
	if err != nil {
		t.Fatal(err)
	}
	var verr ValidationError
	for _, bad := range []WildcardCert{{Domain: "com", DNSProviderID: p.ID}, {Domain: "exa mple.com", DNSProviderID: p.ID}, {Domain: "example.com"}} {
		if _, err := s.SaveWildcard(ctx, bad, "admin"); !errors.As(err, &verr) {
			t.Errorf("accepted %+v", bad)
		}
	}
	w, err := s.SaveWildcard(ctx, WildcardCert{Domain: " *.Example.COM. ", DNSProviderID: p.ID, IncludeApex: true}, "admin")
	if err != nil || w.Domain != "example.com" || w.ID == 0 {
		t.Fatalf("save = %+v, %v", w, err)
	}
	if _, err := s.SaveWildcard(ctx, WildcardCert{Domain: "example.com", DNSProviderID: p.ID}, "admin"); !errors.As(err, &verr) {
		t.Errorf("duplicate accepted: %v", err)
	}
	// The provider can't be deleted while the wildcard uses it.
	if err := s.DeleteDNSProvider(ctx, p.ID, "admin"); err == nil {
		t.Error("deleted a DNS provider a wildcard uses")
	}
	st, _ := s.LoadAccessState(ctx)
	if len(st.Wildcards) != 1 {
		t.Errorf("access state wildcards = %v", st.Wildcards)
	}
	if err := s.DeleteWildcard(ctx, w.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDNSProvider(ctx, p.ID, "admin"); err != nil {
		t.Errorf("delete provider after wildcard removed: %v", err)
	}
}
