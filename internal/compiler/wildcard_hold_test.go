package compiler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/encondata/switchyard/internal/store"
)

func compileJSON(t *testing.T, s Settings, hosts []store.Host, access store.AccessState) map[string]any {
	t.Helper()
	out, err := Compile(s, hosts, access)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestWildcardCertificates(t *testing.T) {
	s := settings
	s.SecretsDir = "/run/cpm-secrets"
	covered := normalized(store.Host{ID: 1, Type: store.Host404, Enabled: true, Domains: []string{"app.example.com"}, TLSMode: store.TLSAuto})
	mixed := normalized(store.Host{ID: 2, Type: store.Host404, Enabled: true, Domains: []string{"shop.example.com", "a.b.example.com"}, TLSMode: store.TLSAuto})
	other := normalized(store.Host{ID: 3, Type: store.Host404, Enabled: true, Domains: []string{"other.org"}, TLSMode: store.TLSAuto})
	access := store.AccessState{Wildcards: []store.WildcardCert{{ID: 1, Domain: "example.com", DNSProviderID: 7, IncludeApex: true}}}
	cfg := compileJSON(t, s, []store.Host{covered, mixed, other}, access)

	srv := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)[HTTPSServer].(map[string]any)
	skip, _ := srv["automatic_https"].(map[string]any)["skip_certificates"].([]any)
	got := []string{}
	for _, v := range skip {
		got = append(got, v.(string))
	}
	if strings.Join(got, ",") != "app.example.com,shop.example.com" {
		t.Errorf("skip_certificates = %v (a.b.example.com and other.org need their own)", got)
	}
	tlsApp := cfg["apps"].(map[string]any)["tls"].(map[string]any)
	automate := tlsApp["certificates"].(map[string]any)["automate"].([]any)
	if len(automate) != 2 || automate[0] != "*.example.com" || automate[1] != "example.com" {
		t.Errorf("automate = %v", automate)
	}
	pol := tlsApp["automation"].(map[string]any)["policies"].([]any)[0].(map[string]any)
	subj := pol["subjects"].([]any)
	if len(subj) != 2 || subj[0] != "*.example.com" {
		t.Errorf("wildcard policy subjects = %v", subj)
	}
	if !strings.Contains(mustJSON(pol), "dns-7.token") {
		t.Errorf("wildcard policy doesn't use provider 7: %s", mustJSON(pol))
	}

	// A DNS-challenge host fully covered by the wildcard needs no provider
	// of its own.
	dnsCovered := normalized(store.Host{ID: 4, Type: store.Host404, Enabled: true, Domains: []string{"vpn.example.com"}, TLSMode: store.TLSDNS})
	if _, err := Compile(s, []store.Host{dnsCovered}, access); err != nil {
		t.Errorf("covered DNS host: %v", err)
	}
	// Without wildcards nothing changes.
	plain := compileJSON(t, s, []store.Host{covered}, store.AccessState{})
	if strings.Contains(mustJSON(plain), "skip_certificates") || strings.Contains(mustJSON(plain), "automate") {
		t.Error("skip/automate without wildcards")
	}
}

func TestHoldDecoy(t *testing.T) {
	until := time.Now().Add(48 * time.Hour)
	held := normalized(store.Host{ID: 9, Type: store.HostProxy, Enabled: true, Domains: []string{"new.example.com"}, TLSMode: store.TLSAuto,
		Upstreams: []store.Upstream{{Host: "10.0.0.5", Port: 8080}}, HoldUntil: &until})
	access := store.AccessState{Honeypot: store.HoneypotState{Settings: store.HoneypotSettings{Response: "login"}}}
	cfg := compileJSON(t, settings, []store.Host{held}, access)
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	ids := func(server string) []string {
		var out []string
		for _, r := range servers[server].(map[string]any)["routes"].([]any) {
			if id, ok := r.(map[string]any)["@id"].(string); ok {
				out = append(out, id)
			}
		}
		return out
	}
	https := strings.Join(ids(HTTPSServer), " ")
	if !strings.Contains(https, "cpm_hold_9_https cpm_host_9") {
		t.Errorf("https routes = %s (decoy must come right before the host)", https)
	}
	if !strings.Contains(strings.Join(ids(HTTPServer), " "), "cpm_hold_9_http cpm_host_9_http") {
		t.Errorf("http routes = %v", ids(HTTPServer))
	}
	j := mustJSON(cfg)
	if !strings.Contains(j, `"value":"hold"`) || !strings.Contains(j, "Administrator sign in") {
		t.Error("decoy isn't the tagged honeypot response")
	}
	if !strings.Contains(j, `"10.0.0.5:8080"`) {
		t.Error("the real route (for the certificate) is missing")
	}
	held.HoldUntil = nil
	if strings.Contains(mustJSON(compileJSON(t, settings, []store.Host{held}, access)), "cpm_hold_") {
		t.Error("decoy after the hold ended")
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
