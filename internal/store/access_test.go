package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func ptr(i int64) *int64 { return &i }

func TestParseRule(t *testing.T) {
	good := map[string]string{
		"10.1.2.3":         "10.1.2.3",
		" 10.1.2.3/8 ":     "10.0.0.0/8",
		"192.168.1.7/32":   "192.168.1.7",
		"2001:db8::1":      "2001:db8::1",
		"2001:db8:1::/48":  "2001:db8:1::/48",
		"::ffff:10.0.0.1":  "10.0.0.1",
		"2001:DB8::5/128":  "2001:db8::5",
		"172.16.40.0/12":   "172.16.0.0/12",
		"203.0.113.0/24":   "203.0.113.0/24",
		"198.51.100.42/31": "198.51.100.42/31",
		// IPv4-mapped IPv6 ranges become the IPv4 range they mean.
		"::ffff:10.0.0.0/104":    "10.0.0.0/8",
		"::ffff:192.168.1.9/120": "192.168.1.0/24",
		"::ffff:10.1.2.3/128":    "10.1.2.3",
	}
	for in, want := range good {
		got, err := ParseRule(in)
		if err != nil || got != want {
			t.Errorf("ParseRule(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if c, err := ParseRule(" de "); err != nil || c != "DE" {
		t.Errorf("country code = %q, %v", c, err)
	}
	for _, bad := range []string{"", "::ffff:0:0/80", "10.0.0.256", "10.0.0.0/33", "example.com", "XX", "10.0.0.1-10.0.0.5"} {
		if _, err := ParseRule(bad); err == nil {
			t.Errorf("ParseRule(%q) accepted", bad)
		}
	}
	if _, err := ParseRule("ZZ"); err == nil || !strings.Contains(err.Error(), "country") {
		t.Errorf("unknown country code error should mention countries: %v", err)
	}
}

func TestFolders(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	prod, err := s.SaveFolder(ctx, Folder{Name: "Production"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	web, err := s.SaveFolder(ctx, Folder{Name: "Web", ParentID: ptr(prod.ID)}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// Same name under another parent is fine; under the same parent it isn't.
	if _, err := s.SaveFolder(ctx, Folder{Name: "Web"}, "admin"); err != nil {
		t.Fatalf("same name at top level: %v", err)
	}
	var verr ValidationError
	if _, err := s.SaveFolder(ctx, Folder{Name: "web", ParentID: ptr(prod.ID)}, "admin"); !errors.As(err, &verr) || verr["name"] == "" {
		t.Fatalf("duplicate sibling name err = %v", err)
	}

	// No cycles: Production can't move inside Web (its own child) or itself.
	prod.ParentID = ptr(web.ID)
	if _, err := s.SaveFolder(ctx, prod, "admin"); !errors.As(err, &verr) || verr["parent_id"] == "" {
		t.Fatalf("cycle err = %v", err)
	}
	prod.ParentID = ptr(prod.ID)
	if _, err := s.SaveFolder(ctx, prod, "admin"); !errors.As(err, &verr) || verr["parent_id"] == "" {
		t.Fatalf("self-parent err = %v", err)
	}

	h := proxyHost("a.example.com")
	h.FolderID = ptr(web.ID)
	h, err = s.SaveHost(ctx, h, "admin")
	if err != nil || h.FolderID == nil || *h.FolderID != web.ID {
		t.Fatalf("host in folder: %+v, %v", h, err)
	}

	// Non-empty folders can't be deleted.
	var conflict ConflictError
	if err := s.DeleteFolder(ctx, prod.ID, "admin"); !errors.As(err, &conflict) {
		t.Fatalf("delete folder with child err = %v", err)
	}
	if err := s.DeleteFolder(ctx, web.ID, "admin"); !errors.As(err, &conflict) {
		t.Fatalf("delete folder with host err = %v", err)
	}

	// Disabling the top folder disables hosts in its subfolders.
	n, err := s.SetFolderEnabled(ctx, prod.ID, false, "admin")
	if err != nil || n != 1 {
		t.Fatalf("SetFolderEnabled = %d, %v", n, err)
	}
	if h, _ = s.GetHost(ctx, h.ID); h.Enabled {
		t.Fatal("host still enabled")
	}

	if _, err := s.MoveHost(ctx, h.ID, nil, "admin", true); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFolder(ctx, web.ID, "admin"); err != nil {
		t.Fatalf("delete empty folder: %v", err)
	}

	h.FolderID = ptr(9999)
	if _, err := s.SaveHost(ctx, h, "admin"); !errors.As(err, &verr) || verr["folder_id"] == "" {
		t.Fatalf("missing folder err = %v", err)
	}
}

func TestPoliciesAndInheritance(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	var verr ValidationError
	if _, err := s.SavePolicy(ctx, AccessPolicy{Name: "x", Mode: PolicyDeny}, "admin"); !errors.As(err, &verr) || verr["rules"] == "" {
		t.Fatalf("empty rules err = %v", err)
	}
	if _, err := s.SavePolicy(ctx, AccessPolicy{Name: "x", Mode: "block", Rules: []string{"1.2.3.4"}}, "admin"); !errors.As(err, &verr) || verr["mode"] == "" {
		t.Fatalf("bad mode err = %v", err)
	}

	lan, err := s.SavePolicy(ctx, AccessPolicy{Name: "LAN only", Mode: PolicyAllowOnly,
		Rules: []string{"10.0.0.0/8", "192.168.1.5/24", "10.0.0.0/8", ""}}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lan.Rules, ",") != "10.0.0.0/8,192.168.1.0/24" || lan.Response != Respond403 {
		t.Fatalf("policy not normalized: %+v", lan)
	}
	if _, err := s.SavePolicy(ctx, AccessPolicy{Name: "lan ONLY", Mode: PolicyDeny, Rules: []string{"1.1.1.1"}}, "admin"); !errors.As(err, &verr) || verr["name"] == "" {
		t.Fatalf("duplicate name err = %v", err)
	}
	bad, _ := s.SavePolicy(ctx, AccessPolicy{Name: "Bad actors", Mode: PolicyDeny, Response: RespondAbort, Rules: []string{"203.0.113.0/24"}}, "admin")

	top, _ := s.SaveFolder(ctx, Folder{Name: "Internal", PolicyIDs: []int64{lan.ID}}, "admin")
	sub, _ := s.SaveFolder(ctx, Folder{Name: "Tools", ParentID: ptr(top.ID), PolicyIDs: []int64{lan.ID, bad.ID}}, "admin")
	h := proxyHost("tools.example.com")
	h.FolderID = ptr(sub.ID)
	h.PolicyIDs = []int64{bad.ID}
	h, err = s.SaveHost(ctx, h, "admin")
	if err != nil {
		t.Fatal(err)
	}

	st, err := s.LoadAccessState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	eff := st.EffectivePolicies(h)
	if len(eff) != 2 {
		t.Fatalf("effective = %+v, want 2 policies (each once)", eff)
	}
	if eff[0].ID != bad.ID || eff[0].FromFolderID != nil {
		t.Errorf("first should be the host's own deny policy: %+v", eff[0])
	}
	if eff[1].ID != lan.ID || eff[1].FromFolderID == nil || *eff[1].FromFolderID != sub.ID {
		t.Errorf("LAN policy should come from the nearest folder (Tools): %+v", eff[1])
	}

	// Policies in use can't be deleted.
	var conflict ConflictError
	if err := s.DeletePolicy(ctx, lan.ID, "admin"); !errors.As(err, &conflict) {
		t.Fatalf("delete used policy err = %v", err)
	}
	ps, _ := s.ListPolicies(ctx)
	for _, p := range ps {
		if p.ID == lan.ID && (p.FolderCount != 2 || p.HostCount != 0) {
			t.Errorf("LAN usage = %d folders, %d hosts", p.FolderCount, p.HostCount)
		}
	}
}

func TestNeverBan(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	nb, err := s.AddNeverBan(ctx, "192.168.1.10/24", "office", "admin")
	if err != nil || nb.CIDR != "192.168.1.0/24" {
		t.Fatalf("AddNeverBan = %+v, %v", nb, err)
	}
	var verr ValidationError
	if _, err := s.AddNeverBan(ctx, "192.168.1.0/24", "", "admin"); !errors.As(err, &verr) {
		t.Fatalf("duplicate err = %v", err)
	}
	if _, err := s.AddNeverBan(ctx, "nope", "", "admin"); !errors.As(err, &verr) {
		t.Fatalf("invalid err = %v", err)
	}
	if err := s.DeleteNeverBan(ctx, "192.168.1.0/24", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNeverBan(ctx, "192.168.1.0/24", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete err = %v", err)
	}
}
