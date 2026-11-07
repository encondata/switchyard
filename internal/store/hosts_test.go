package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func proxyHost(domains ...string) Host {
	return Host{
		Type: HostProxy, Enabled: true, Domains: domains, TLSMode: TLSInternal,
		Upstreams: []Upstream{{Host: "app", Port: 8080}},
	}
}

func TestSaveAndListHosts(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	h, err := s.SaveHost(ctx, proxyHost(" App.Example.COM. ", "www.example.com"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if h.ID == 0 || h.Domains[0] != "app.example.com" || h.Upstreams[0].Scheme != "http" {
		t.Fatalf("saved host not normalized: %+v", h)
	}

	h.Enabled = false
	h.Domains = []string{"app.example.com"}
	if h, err = s.SaveHost(ctx, h, "admin"); err != nil {
		t.Fatal(err)
	}
	if h.Enabled || len(h.Domains) != 1 {
		t.Fatalf("update not saved: %+v", h)
	}

	// www.example.com was freed by the update, so another host can take it.
	if _, err := s.SaveHost(ctx, proxyHost("www.example.com"), "admin"); err != nil {
		t.Fatalf("freed domain: %v", err)
	}
	_, err = s.SaveHost(ctx, proxyHost("APP.example.com"), "admin")
	var verr ValidationError
	if !errors.As(err, &verr) || !strings.Contains(verr["domains"], "already used") {
		t.Fatalf("duplicate domain err = %v", err)
	}

	hosts, err := s.ListHosts(ctx)
	if err != nil || len(hosts) != 2 {
		t.Fatalf("ListHosts = %d hosts, %v", len(hosts), err)
	}

	if err := s.DeleteHost(ctx, h.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetHost(ctx, h.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted host err = %v", err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE entity = 'host'`).Scan(&n)
	if n != 4 {
		t.Fatalf("audit rows = %d, want 4", n)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]struct {
		host  Host
		field string
	}{
		"no domains":       {Host{Type: HostProxy, Upstreams: []Upstream{{Host: "a"}}}, "domains"},
		"bad domain":       {proxyHost("bad_domain.com"), "domains"},
		"ip as domain":     {proxyHost("10.0.0.1"), "domains"},
		"repeat domain":    {proxyHost("a.com", "A.com"), "domains"},
		"wildcard on auto": {Host{Type: Host404, Domains: []string{"*.a.com"}, TLSMode: TLSAuto}, "domains"},
		"no upstream":      {Host{Type: HostProxy, Domains: []string{"a.com"}}, "upstreams"},
		"bad upstream":     {Host{Type: HostProxy, Domains: []string{"a.com"}, Upstreams: []Upstream{{Host: "a b"}}}, "upstreams"},
		"bad port":         {Host{Type: HostProxy, Domains: []string{"a.com"}, Upstreams: []Upstream{{Host: "a", Port: 70000}}}, "upstreams"},
		"bad redirect":     {Host{Type: HostRedirect, Domains: []string{"a.com"}, RedirectTo: "example.com"}, "redirect_to"},
		"bad code":         {Host{Type: HostRedirect, Domains: []string{"a.com"}, RedirectTo: "https://b.com", RedirectCode: 200}, "redirect_code"},
		"bad type":         {Host{Type: "stream", Domains: []string{"a.com"}}, "type"},
	}
	for name, c := range cases {
		h := c.host
		h.Normalize()
		var verr ValidationError
		if err := h.Validate(); !errors.As(err, &verr) || verr[c.field] == "" {
			t.Errorf("%s: err = %v, want a %s error", name, err, c.field)
		}
	}

	ok := []Host{
		proxyHost("app.localhost"),
		{Type: Host404, Domains: []string{"*.lan.example.com"}, TLSMode: TLSInternal},
		{Type: HostRedirect, Domains: []string{"old.example.com"}, RedirectTo: "https://new.example.com/x"},
		{Type: HostProxy, Domains: []string{"x.example.com"}, Upstreams: []Upstream{{Scheme: "https", Host: "10.0.0.5"}}},
	}
	for _, h := range ok {
		h.Normalize()
		if err := h.Validate(); err != nil {
			t.Errorf("%v: unexpected error %v", h.Domains, err)
		}
	}
}

func TestConfigVersions(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.LastAppliedConfig(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty LastAppliedConfig err = %v", err)
	}
	n1, _ := s.AddConfigVersion(ctx, ConfigVersion{JSON: "{}", SHA256: "a", AppliedBy: "admin", Result: "ok"})
	_, _ = s.AddConfigVersion(ctx, ConfigVersion{JSON: "{x}", SHA256: "b", AppliedBy: "admin", Result: "failed", Error: "boom"})
	last, err := s.LastAppliedConfig(ctx)
	if err != nil || last.N != n1 {
		t.Fatalf("LastAppliedConfig = %+v, %v; want n=%d", last, err, n1)
	}
	list, _ := s.ListConfigVersions(ctx, 10)
	if len(list) != 2 || list[0].Result != "failed" || list[0].JSON != "" {
		t.Fatalf("ListConfigVersions = %+v", list)
	}
}
