package compiler

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encondata/caddyproxymanager/internal/store"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

var settings = Settings{AdminListen: "unix//run/caddy/admin.sock|0660"}

func normalized(h store.Host) store.Host {
	h.Normalize()
	if err := h.Validate(); err != nil {
		panic(err)
	}
	return h
}

// Golden-file cases: database state in, expected Caddy JSON out (spec §8).
var cases = map[string][]store.Host{
	"empty": nil,
	"proxy_auto_https": {normalized(store.Host{
		ID: 1, Type: store.HostProxy, Enabled: true, Domains: []string{"app.example.com", "www.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.5", Port: 3000}}, TLSMode: store.TLSAuto,
		ForceHTTPS: true, HSTS: true, Compression: true,
	})},
	"proxy_internal_no_force": {normalized(store.Host{
		ID: 2, Type: store.HostProxy, Enabled: true, Domains: []string{"nas.lan.example.com"},
		Upstreams: []store.Upstream{
			{Scheme: "https", Host: "nas", Port: 5001, SkipTLSVerify: true},
			{Scheme: "https", Host: "nas-backup", Port: 5001, SkipTLSVerify: true},
		},
		LoadBalancing: "first", TLSMode: store.TLSInternal,
	})},
	"mixed": {
		normalized(store.Host{
			ID: 3, Type: store.HostProxy, Enabled: true, Domains: []string{"app.localhost"},
			Upstreams: []store.Upstream{{Host: "whoami"}}, TLSMode: store.TLSOff, Compression: true,
		}),
		normalized(store.Host{
			ID: 4, Type: store.HostRedirect, Enabled: true, Domains: []string{"old.example.com"},
			RedirectTo: "https://new.example.com/", RedirectCode: 308, PreservePath: true,
			TLSMode: store.TLSAuto, ForceHTTPS: true,
		}),
		normalized(store.Host{
			ID: 5, Type: store.Host404, Enabled: true, Domains: []string{"*.parked.example.com"},
			TLSMode: store.TLSInternal, ForceHTTPS: true,
		}),
		normalized(store.Host{
			ID: 6, Type: store.HostProxy, Enabled: false, Domains: []string{"disabled.example.com"},
			Upstreams: []store.Upstream{{Host: "x"}},
		}),
	},
}

func TestGolden(t *testing.T) {
	for name, hosts := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Compile(settings, hosts, store.AccessState{})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", name+".json")
			if *update {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run `go test ./internal/compiler -update` to create it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("config for %s differs from %s; run with -update if the change is intended.\n--- got ---\n%s", name, path, got)
			}
		})
	}
}

func TestDeterministic(t *testing.T) {
	a, _ := Compile(settings, cases["mixed"], store.AccessState{})
	reversed := append([]store.Host(nil), cases["mixed"]...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	b, _ := Compile(settings, reversed, store.AccessState{})
	if !bytes.Equal(a, b) {
		t.Fatal("host order changed the output")
	}
}

// Caddy refuses a config in which two objects share an @id (and
// `caddy validate` doesn't catch it), so check every case.
func TestUniqueIDs(t *testing.T) {
	for name, hosts := range cases {
		out, err := Compile(settings, hosts, store.AccessState{})
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		var walk func(any)
		walk = func(n any) {
			switch x := n.(type) {
			case map[string]any:
				if id, ok := x["@id"].(string); ok {
					if seen[id] {
						t.Errorf("%s: duplicate @id %q", name, id)
					}
					seen[id] = true
				}
				for _, c := range x {
					walk(c)
				}
			case []any:
				for _, c := range x {
					walk(c)
				}
			}
		}
		walk(v)
	}
}

func TestAdminListenRequired(t *testing.T) {
	if _, err := Compile(Settings{}, nil, store.AccessState{}); err == nil {
		t.Fatal("expected an error without AdminListen")
	}
}

// accessState: folder "Internal" (allow-only LAN) > "Tools" (deny
// bad range, abort), plus a never-ban office address.
func accessState() store.AccessState {
	internal, tools := int64(10), int64(11)
	return store.AccessState{
		Folders: map[int64]store.Folder{
			internal: {ID: internal, Name: "Internal", PolicyIDs: []int64{1}},
			tools:    {ID: tools, Name: "Tools", ParentID: &internal, PolicyIDs: []int64{2}},
		},
		Policies: map[int64]store.AccessPolicy{
			1: {ID: 1, Name: "LAN only", Mode: store.PolicyAllowOnly, Response: store.Respond403, Rules: []string{"10.0.0.0/8", "192.168.0.0/16"}},
			2: {ID: 2, Name: "Bad range", Mode: store.PolicyDeny, Response: store.RespondAbort, Rules: []string{"10.66.0.0/16"}},
			3: {ID: 3, Name: "VPN", Mode: store.PolicyAllowOnly, Response: store.RespondAbort, Rules: []string{"100.64.0.0/10"}},
		},
		NeverBan: []string{"203.0.113.7"},
	}
}

func accessHosts() []store.Host {
	tools := int64(11)
	return []store.Host{
		// Inherits LAN-only (from Internal) and Bad range (from Tools), and
		// adds VPN itself: allow-only ranges are combined, abort wins.
		normalized(store.Host{
			ID: 1, Type: store.HostProxy, Enabled: true, Domains: []string{"tools.localhost"},
			Upstreams: []store.Upstream{{Host: "whoami"}}, TLSMode: store.TLSOff,
			FolderID: &tools, PolicyIDs: []int64{3},
		}),
		// No folder, no policies: no access routes.
		normalized(store.Host{
			ID: 2, Type: store.HostProxy, Enabled: true, Domains: []string{"open.localhost"},
			Upstreams: []store.Upstream{{Host: "whoami"}}, TLSMode: store.TLSOff,
		}),
	}
}

func TestGoldenAccess(t *testing.T) {
	got, err := Compile(settings, accessHosts(), accessState())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "access.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("access config differs from %s; run with -update if intended.\n%s", path, got)
	}
}

func TestGoldenDNS(t *testing.T) {
	cf := int64(7)
	lan := int64(20)
	access := store.AccessState{
		Folders:  map[int64]store.Folder{lan: {ID: lan, Name: "LAN", DNSProviderID: &cf}},
		Policies: map[int64]store.AccessPolicy{},
	}
	hosts := []store.Host{
		normalized(store.Host{
			ID: 1, Type: store.HostProxy, Enabled: true, Domains: []string{"nas.lan.example.com", "*.lan.example.com"},
			Upstreams: []store.Upstream{{Host: "nas", Port: 5000}}, TLSMode: store.TLSDNS, ForceHTTPS: true,
			FolderID: &lan,
		}),
		normalized(store.Host{
			ID: 2, Type: store.HostProxy, Enabled: true, Domains: []string{"www.example.com"},
			Upstreams: []store.Upstream{{Host: "web"}}, TLSMode: store.TLSAuto, ForceHTTPS: true,
		}),
	}
	st := Settings{
		AdminListen: settings.AdminListen, SecretsDir: "/run/cpm-secrets",
		ACMECA: "https://acme-staging-v02.api.letsencrypt.org/directory", ACMEEmail: "ops@example.com",
	}
	got, err := Compile(st, hosts, access)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("api_token\": \"A")) {
		t.Fatal("a literal token leaked into the config")
	}
	path := filepath.Join("testdata", "dns.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("dns config differs from %s; run with -update if intended.\n%s", path, got)
	}

	// No provider anywhere: compile fails with a clear message.
	hosts[0].FolderID = nil
	if _, err := Compile(st, hosts, access); err == nil {
		t.Fatal("expected an error for a DNS host without a provider")
	}
}

func TestHeaderOps(t *testing.T) {
	rules := []store.HeaderRule{
		{Op: "set", Name: "X-Frame-Options", Value: "DENY"},
		{Op: "delete", Name: "Server"},
		{Op: "add", Name: "X-Tag", Value: "a"},
		{Op: "add", Name: "X-Tag", Value: "b"},
		{Op: "set", Name: "X-Env", Value: "prod"},
		{Op: "add", Name: "x-env", Value: "eu"},   // set then add: keep both
		{Op: "set", Name: "Server", Value: "cpm"}, // later set beats earlier delete
		{Op: "delete", Name: "X-Frame-Options"},   // later delete beats earlier set
	}
	got, _ := json.Marshal(headerOps(rules))
	want := `{"add":{"X-Tag":["a","b"]},"delete":["X-Frame-Options"],"set":{"Server":["cpm"],"X-Env":["prod","eu"]}}`
	if string(got) != want {
		t.Fatalf("headerOps =\n%s\nwant\n%s", got, want)
	}
	if headerOps(nil) != nil {
		t.Fatal("no rules should give no ops")
	}
}

func TestGoldenFeatures(t *testing.T) {
	folder := int64(30)
	access := store.AccessState{
		Folders: map[int64]store.Folder{folder: {ID: folder, Name: "Apps",
			ResponseHeaders: []store.HeaderRule{{Op: "set", Name: "X-Frame-Options", Value: "SAMEORIGIN"}, {Op: "delete", Name: "Server"}},
			RequestHeaders:  []store.HeaderRule{{Op: "set", Name: "X-Real-IP", Value: "{http.request.remote.host}"}},
		}},
		Policies: map[int64]store.AccessPolicy{1: {ID: 1, Name: "Deny", Mode: store.PolicyDeny, Response: store.Respond403, Rules: []string{"192.0.2.0/24"}}},
	}
	hosts := []store.Host{normalized(store.Host{
		ID: 1, Type: store.HostProxy, Enabled: true, Domains: []string{"app.localhost"}, TLSMode: store.TLSOff,
		Upstreams:       []store.Upstream{{Host: "a"}, {Host: "b"}},
		FolderID:        &folder,
		PolicyIDs:       []int64{1},
		ResponseHeaders: []store.HeaderRule{{Op: "set", Name: "X-Frame-Options", Value: "DENY"}},
		HealthCheckPath: "/health", HealthCheckInterval: 15,
		AdvancedJSON: `[{"match":[{"path":["/static/*"]}],"handle":[{"handler":"static_response","body":"static"}],"terminal":true}]`,
	})}
	got, err := Compile(settings, hosts, access)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "features.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("features config differs from %s; run with -update if intended.\n%s", path, got)
	}
}

func TestCountryRules(t *testing.T) {
	access := store.AccessState{
		Folders: map[int64]store.Folder{},
		Policies: map[int64]store.AccessPolicy{
			1: {ID: 1, Name: "Home", Mode: store.PolicyAllowOnly, Response: store.Respond403, Rules: []string{"US", "CA", "10.0.0.0/8"}},
			2: {ID: 2, Name: "No RU", Mode: store.PolicyDeny, Response: store.RespondAbort, Rules: []string{"RU"}},
		},
	}
	hosts := []store.Host{normalized(store.Host{
		ID: 1, Type: store.Host404, Enabled: true, Domains: []string{"geo.localhost"}, TLSMode: store.TLSOff, PolicyIDs: []int64{1, 2},
	})}
	if _, err := Compile(settings, hosts, access); err == nil || !strings.Contains(err.Error(), "GeoLite2") {
		t.Fatalf("country rules without a database err = %v", err)
	}
	st := settings
	st.GeoIPDB, st.GeoIPReady = "/usr/share/GeoIP/GeoLite2-Country.mmdb", true
	got, err := Compile(st, hosts, access)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "geo.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, _ := os.ReadFile(path)
	if !bytes.Equal(got, want) {
		t.Errorf("geo config differs from %s; run with -update if intended.\n%s", path, got)
	}
}
