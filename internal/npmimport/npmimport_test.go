package npmimport

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encondata/caddyproxymanager/internal/store"
)

// fixture builds a small NPM 2.x database (column names as NPM uses them).
func fixture(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "database.sqlite")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stmts := []string{
		`CREATE TABLE certificate (id INTEGER PRIMARY KEY, is_deleted INTEGER DEFAULT 0, provider TEXT, nice_name TEXT, domain_names TEXT, meta TEXT)`,
		`CREATE TABLE access_list (id INTEGER PRIMARY KEY, is_deleted INTEGER DEFAULT 0, name TEXT, satisfy_any INTEGER, pass_auth INTEGER, meta TEXT)`,
		`CREATE TABLE access_list_client (id INTEGER PRIMARY KEY, access_list_id INTEGER, address TEXT, directive TEXT, meta TEXT)`,
		`CREATE TABLE access_list_auth (id INTEGER PRIMARY KEY, access_list_id INTEGER, username TEXT, password TEXT, meta TEXT)`,
		`CREATE TABLE proxy_host (id INTEGER PRIMARY KEY, is_deleted INTEGER DEFAULT 0, domain_names TEXT, forward_host TEXT,
			forward_port INTEGER, access_list_id INTEGER, certificate_id INTEGER, ssl_forced INTEGER, caching_enabled INTEGER,
			block_exploits INTEGER, advanced_config TEXT, meta TEXT, allow_websocket_upgrade INTEGER, http2_support INTEGER,
			forward_scheme TEXT, enabled INTEGER, locations TEXT, hsts_enabled INTEGER, hsts_subdomains INTEGER)`,
		`CREATE TABLE redirection_host (id INTEGER PRIMARY KEY, is_deleted INTEGER DEFAULT 0, domain_names TEXT, forward_domain_name TEXT,
			preserve_path INTEGER, certificate_id INTEGER, ssl_forced INTEGER, block_exploits INTEGER, advanced_config TEXT, meta TEXT,
			http2_support INTEGER, enabled INTEGER, hsts_enabled INTEGER, hsts_subdomains INTEGER, forward_http_code INTEGER, forward_scheme TEXT)`,
		`CREATE TABLE dead_host (id INTEGER PRIMARY KEY, is_deleted INTEGER DEFAULT 0, domain_names TEXT, certificate_id INTEGER,
			ssl_forced INTEGER, advanced_config TEXT, meta TEXT, http2_support INTEGER, enabled INTEGER, hsts_enabled INTEGER, hsts_subdomains INTEGER)`,
		`CREATE TABLE stream (id INTEGER PRIMARY KEY, is_deleted INTEGER DEFAULT 0, incoming_port INTEGER, forwarding_host TEXT,
			forwarding_port INTEGER, tcp_forwarding INTEGER, udp_forwarding INTEGER, meta TEXT, enabled INTEGER)`,

		`INSERT INTO certificate VALUES (1, 0, 'letsencrypt', 'app', '["app.example.com"]', '{"letsencrypt_agree":true}')`,
		`INSERT INTO certificate VALUES (2, 0, 'letsencrypt', 'wild', '["*.lan.example.com"]', '{"dns_challenge":true,"dns_provider":"cloudflare"}')`,

		`INSERT INTO access_list VALUES (1, 0, 'Office', 0, 0, '{}')`,
		`INSERT INTO access_list_client VALUES (1, 1, '203.0.113.0/24', 'allow', '{}')`,
		`INSERT INTO access_list_client VALUES (2, 1, '198.51.100.7', 'deny', '{}')`,
		`INSERT INTO access_list_client VALUES (3, 1, 'all', 'deny', '{}')`,
		`INSERT INTO access_list_auth VALUES (1, 1, 'bob', 'secret', '{}')`,

		`INSERT INTO proxy_host VALUES (1, 0, '["app.example.com","www.example.com"]', '10.0.0.5', 3000, 1, 1, 1, 0, 1, '', '{}', 1, 1, 'http', 1, '[]', 1, 0)`,
		`INSERT INTO proxy_host VALUES (2, 0, '["nas.lan.example.com","*.lan.example.com"]', 'nas', 5001, 0, 2, 1, 0, 0,
			'proxy_set_header X-Custom 1;', '{}', 0, 1, 'https', 0, '[{"path":"/api"}]', 0, 0)`,
		`INSERT INTO proxy_host VALUES (3, 0, '["plain.example.com"]', '10.0.0.9', 80, 0, 0, 0, 0, 0, '', '{}', 0, 0, 'http', 1, NULL, 0, 0)`,
		`INSERT INTO proxy_host VALUES (4, 1, '["deleted.example.com"]', 'x', 80, 0, 0, 0, 0, 0, '', '{}', 0, 0, 'http', 1, NULL, 0, 0)`,
		`INSERT INTO proxy_host VALUES (5, 0, '["taken.example.com"]', 'x', 80, 0, 0, 0, 0, 0, '', '{}', 0, 0, 'http', 1, NULL, 0, 0)`,
		`INSERT INTO redirection_host VALUES (1, 0, '["old.example.com"]', 'new.example.com', 1, 1, 1, 0, '', '{}', 0, 1, 0, 0, 308, 'https')`,
		`INSERT INTO redirection_host VALUES (2, 0, '["odd.example.com"]', 'new.example.com', 0, 0, 0, 0, '', '{}', 0, 1, 0, 0, 300, 'auto')`,
		`INSERT INTO dead_host VALUES (1, 0, '["parked.example.com"]', 0, 0, '', '{}', 0, 1, 0, 0)`,
		`INSERT INTO stream VALUES (1, 0, 2222, '10.0.0.20', 22, 1, 0, '{}', 1)`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return db
}

func find(p Plan, source string) PlannedHost {
	for _, h := range p.Hosts {
		if h.Source == source {
			return h
		}
	}
	return PlannedHost{}
}

func TestBuildAndApply(t *testing.T) {
	ctx := context.Background()
	db := fixture(t)

	p, err := Build(ctx, db, Options{ExistingDomains: map[string]bool{"taken.example.com": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hosts) != 7 {
		t.Fatalf("hosts = %d, want 7 (deleted ones left out)", len(p.Hosts))
	}

	app := find(p, "proxy_host #1")
	if app.Host.TLSMode != store.TLSAuto || !app.Host.ForceHTTPS || !app.Host.HSTS || app.Host.Enabled ||
		app.Host.Upstreams[0].Dial() != "10.0.0.5:3000" || len(app.Policies) != 2 {
		t.Fatalf("proxy_host #1 = %+v", app)
	}
	nas := find(p, "proxy_host #2")
	if nas.Host.TLSMode != store.TLSInternal || nas.Host.Upstreams[0].Scheme != "https" || len(nas.Warnings) < 2 ||
		!strings.Contains(nas.Host.Notes, "X-Custom") || nas.Skip != "" {
		t.Fatalf("proxy_host #2 = %+v", nas)
	}
	if plain := find(p, "proxy_host #3"); plain.Host.TLSMode != store.TLSOff {
		t.Fatalf("no cert should mean TLS off: %+v", plain.Host)
	}
	if taken := find(p, "proxy_host #5"); taken.Skip == "" {
		t.Fatal("existing domain not skipped")
	}
	red := find(p, "redirection_host #1")
	if red.Host.RedirectTo != "https://new.example.com" || red.Host.RedirectCode != 308 || !red.Host.PreservePath {
		t.Fatalf("redirect = %+v", red.Host)
	}
	if odd := find(p, "redirection_host #2"); odd.Host.RedirectCode != 302 || len(odd.Warnings) == 0 {
		t.Fatalf("odd redirect = %+v", odd)
	}
	if dead := find(p, "dead_host #1"); dead.Host.Type != store.Host404 {
		t.Fatalf("dead host = %+v", dead.Host)
	}
	if len(p.Policies) != 2 || p.Policies[0].Policy.Rules[0] != "203.0.113.0/24" || p.Policies[1].Policy.Mode != store.PolicyDeny {
		t.Fatalf("policies = %+v", p.Policies)
	}
	if len(p.Streams) != 1 || p.Streams[0].Forward != "10.0.0.20:22" {
		t.Fatalf("streams = %+v", p.Streams)
	}
	joined := strings.Join(p.Warnings, " ")
	if !strings.Contains(joined, "basic auth") || !strings.Contains(joined, "stream") {
		t.Fatalf("warnings = %v", p.Warnings)
	}

	// With a DNS provider, the wildcard host uses the DNS challenge.
	p2, _ := Build(ctx, db, Options{DNSProviderID: 9})
	if h := find(p2, "proxy_host #2").Host; h.TLSMode != store.TLSDNS || h.DNSProviderID == nil || *h.DNSProviderID != 9 {
		t.Fatalf("dns host = %+v", h)
	}

	// Apply into a real store.
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.SaveHost(ctx, store.Host{Type: store.Host404, Enabled: true, Domains: []string{"taken.example.com"}, TLSMode: store.TLSOff}, "admin"); err != nil {
		t.Fatal(err)
	}
	res, err := Apply(ctx, st, p, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if res.HostsCreated != 6 || res.PoliciesCreated != 2 || len(res.Skipped) != 1 {
		t.Fatalf("result = %+v", res)
	}
	hosts, _ := st.ListHosts(ctx)
	for _, h := range hosts {
		if h.Domains[0] == "taken.example.com" {
			continue
		}
		if h.Enabled || h.FolderID == nil || *h.FolderID != res.FolderID {
			t.Errorf("imported host %v should be disabled in the Imported folder", h.Domains)
		}
	}
	// Importing again doesn't duplicate policies or the folder.
	again, _ := Apply(ctx, st, p, "admin")
	if again.PoliciesCreated != 0 || again.FolderID != res.FolderID || again.HostsCreated != 0 {
		t.Fatalf("second import = %+v", again)
	}
}

func TestNotNPM(t *testing.T) {
	db, _ := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "x.db"))
	defer func() { _ = db.Close() }()
	if _, err := Build(context.Background(), db, Options{}); err == nil {
		t.Fatal("expected an error for a non-NPM database")
	}
}
