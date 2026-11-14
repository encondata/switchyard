package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMailDomains(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	box := testBox(t)
	p, err := s.SaveDNSProvider(ctx, DNSProvider{Name: "cf"}, cfToken, box, "admin")
	if err != nil {
		t.Fatal(err)
	}

	var verr ValidationError
	if _, err := s.CreateMailDomain(ctx, MailDomain{Domain: "not a domain", DNSProviderID: p.ID, ZoneID: "z", ZoneName: "z"}, "admin"); !errors.As(err, &verr) || verr["domain"] == "" {
		t.Fatalf("bad domain err = %v", err)
	}
	if _, err := s.CreateMailDomain(ctx, MailDomain{Domain: "example.com", DNSProviderID: 99, ZoneID: "z", ZoneName: "z"}, "admin"); !errors.As(err, &verr) || verr["dns_provider_id"] == "" {
		t.Fatalf("bad provider err = %v", err)
	}
	m, err := s.CreateMailDomain(ctx, MailDomain{Domain: "Example.COM.", DNSProviderID: p.ID, ZoneID: "z1", ZoneName: "example.com"}, "admin")
	if err != nil || m.Domain != "example.com" || m.Status != "" || m.CheckedAt != nil {
		t.Fatalf("create = %+v, %v", m, err)
	}
	if _, err := s.CreateMailDomain(ctx, MailDomain{Domain: "example.com", DNSProviderID: p.ID, ZoneID: "z1", ZoneName: "example.com"}, "admin"); !errors.As(err, &verr) || verr["domain"] == "" {
		t.Fatalf("duplicate err = %v", err)
	}

	if err := s.SetMailStatus(ctx, m.ID, "conflict", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if m, _ = s.GetMailDomain(ctx, m.ID); m.Status != "conflict" || m.CheckedAt == nil {
		t.Fatalf("after status = %+v", m)
	}

	// The provider can't go while a mail domain uses it.
	var conflict ConflictError
	if err := s.DeleteDNSProvider(ctx, p.ID, "admin"); !errors.As(err, &conflict) {
		t.Fatalf("delete provider err = %v", err)
	}
	if err := s.DeleteMailDomain(ctx, m.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if ds, _ := s.ListMailDomains(ctx); len(ds) != 0 {
		t.Fatalf("after delete = %+v", ds)
	}
	if err := s.DeleteDNSProvider(ctx, p.ID, "admin"); err != nil {
		t.Fatalf("delete provider after = %v", err)
	}
}

func TestPurelymailOwnership(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	since := time.Now().Add(-time.Second)
	v, err := s.SavePurelymailOwnership(ctx, `  "purelymail_ownership_proof=abc"  `, "admin")
	if err != nil || v != "purelymail_ownership_proof=abc" {
		t.Fatalf("save = %q, %v", v, err)
	}
	if got, _ := s.PurelymailOwnership(ctx); got != v {
		t.Fatalf("get = %q", got)
	}
	var verr ValidationError
	if _, err := s.SavePurelymailOwnership(ctx, "two\nlines", "admin"); !errors.As(err, &verr) {
		t.Fatalf("bad value err = %v", err)
	}
	// Mail settings aren't Caddy config: nothing pending to apply.
	if n, err := s.ChangesSince(ctx, since); err != nil || n != 0 {
		t.Fatalf("ChangesSince = %d, %v", n, err)
	}
}
