package npmimport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/encondata/switchyard/internal/store"
)

// fakeNPM answers like NPM 2.x's API.
func fakeNPM(t *testing.T) *httptest.Server {
	t.Helper()
	data := map[string]string{
		"/api/nginx/proxy-hosts": `[{"id":1,"domain_names":["app.example.com"],"forward_scheme":"http","forward_host":"10.0.0.5","forward_port":8080,
			"certificate_id":3,"ssl_forced":true,"hsts_enabled":false,"access_list_id":2,"advanced_config":"","locations":[],"meta":{},"enabled":true},
			{"id":2,"domain_names":["old.example.com"],"forward_scheme":"https","forward_host":"10.0.0.6","forward_port":443,"certificate_id":0,"enabled":false}]`,
		"/api/nginx/redirection-hosts": `[{"id":4,"domain_names":["www.example.com"],"forward_scheme":"https","forward_domain_name":"example.com","forward_http_code":301,"preserve_path":true,"certificate_id":0,"enabled":1}]`,
		"/api/nginx/dead-hosts":        `[]`,
		"/api/nginx/streams":           `[{"id":7,"incoming_port":2222,"forwarding_host":"10.0.0.9","forwarding_port":22,"tcp_forwarding":true,"udp_forwarding":false,"enabled":true}]`,
		"/api/nginx/certificates":      `[{"id":3,"provider":"letsencrypt","domain_names":["app.example.com"],"meta":{"dns_challenge":false}}]`,
		"/api/nginx/access-lists":      `[{"id":2,"name":"Office","items":[],"clients":[{"address":"192.168.1.0/24","directive":"allow"},{"address":"all","directive":"deny"}]}]`,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tokens" {
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["identity"] != "admin@example.com" || b["secret"] != "pw" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":401,"message":"Invalid email or password"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"token":"tok","expires":"2099-01-01"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/nginx/access-lists" && r.URL.Query().Get("expand") != "items,clients" {
			t.Errorf("access lists fetched without expand: %s", r.URL)
		}
		body, ok := data[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
}

func TestFetchAPI(t *testing.T) {
	srv := fakeNPM(t)
	defer srv.Close()
	ctx := context.Background()

	// A pasted ".../api/" path is fine.
	src, err := FetchAPI(ctx, APIConfig{URL: srv.URL + "/api/", Email: "admin@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build(ctx, src, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hosts) != 3 {
		t.Fatalf("hosts = %d, want 3: %+v", len(p.Hosts), p.Hosts)
	}
	byDomain := map[string]PlannedHost{}
	for _, h := range p.Hosts {
		byDomain[h.Host.Domains[0]] = h
	}
	app := byDomain["app.example.com"]
	if app.Skip != "" || app.Host.TLSMode != store.TLSAuto || !app.Host.ForceHTTPS || len(app.Host.Upstreams) != 1 ||
		app.Host.Upstreams[0].Host != "10.0.0.5" || app.Host.Upstreams[0].Port != 8080 {
		t.Errorf("app host = %+v", app)
	}
	if len(app.Policies) != 1 || app.Policies[0] != "NPM: Office" {
		t.Errorf("app policies = %v", app.Policies)
	}
	if !strings.Contains(byDomain["old.example.com"].Host.Notes, "disabled in NPM") {
		t.Errorf("old host notes = %q", byDomain["old.example.com"].Host.Notes)
	}
	www := byDomain["www.example.com"]
	if www.Host.Type != store.HostRedirect || www.Host.RedirectTo != "https://example.com" || www.Host.RedirectCode != 301 || !www.Host.PreservePath {
		t.Errorf("redirect = %+v", www.Host)
	}
	if len(p.Policies) != 1 || p.Policies[0].Policy.Rules[0] != "192.168.1.0/24" {
		t.Errorf("policies = %+v", p.Policies)
	}
	if len(p.Streams) != 1 || p.Streams[0].IncomingPort != 2222 || p.Streams[0].Protocols != "TCP" {
		t.Errorf("streams = %+v", p.Streams)
	}
}

func TestFetchAPIErrors(t *testing.T) {
	srv := fakeNPM(t)
	defer srv.Close()
	ctx := context.Background()
	for _, tc := range []struct {
		cfg  APIConfig
		want string
	}{
		{APIConfig{URL: srv.URL, Email: "admin@example.com", Password: "nope"}, "didn't accept"},
		{APIConfig{URL: "ftp://x", Email: "a", Password: "b"}, "enter NPM's address"},
		{APIConfig{URL: srv.URL, Email: "", Password: "b"}, "email and password"},
		{APIConfig{URL: "http://127.0.0.1:1", Email: "a", Password: "b"}, "can't reach NPM"},
	} {
		if _, err := FetchAPI(ctx, tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("FetchAPI(%+v) = %v, want error containing %q", tc.cfg.URL, err, tc.want)
		}
	}
}
