// Package integration runs CPM end to end against a real Caddy and Pebble
// (Let's Encrypt's test CA) started by run.sh (spec §8, CPM-6). It's
// skipped unless CPM_INTEGRATION=1.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"
	"time"
)

type env struct {
	t         *testing.T
	cpm       string
	caddyHTTP string
	caddyTLS  string
	api       *http.Client
}

func setup(t *testing.T) *env {
	t.Helper()
	if os.Getenv("CPM_INTEGRATION") == "" {
		t.Skip("set CPM_INTEGRATION=1 (run tests/integration/run.sh)")
	}
	jar, _ := cookiejar.New(nil)
	e := &env{
		t: t, cpm: os.Getenv("CPM_URL"), caddyHTTP: os.Getenv("CADDY_HTTP"), caddyTLS: os.Getenv("CADDY_HTTPS"),
		api: &http.Client{Jar: jar, Timeout: 90 * time.Second},
	}
	e.waitFor("CPM to answer", 60*time.Second, func() bool {
		resp, err := http.Get(e.cpm + "/api/health")
		if err == nil {
			_ = resp.Body.Close()
		}
		return err == nil && resp.StatusCode == 200
	})
	if code, body := e.call("POST", "/api/auth/login", `{"username":"admin","password":"123456"}`); code != 200 {
		t.Fatalf("first sign-in = %d %s", code, body)
	}
	if code, body := e.call("POST", "/api/auth/password", `{"current_password":"123456","new_password":"integration-pass-1"}`); code != 200 {
		t.Fatalf("password change = %d %s", code, body)
	}
	return e
}

func (e *env) call(method, path, body string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.cpm+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.api.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) json(method, path, body string, out any) int {
	e.t.Helper()
	code, b := e.call(method, path, body)
	if out != nil {
		_ = json.Unmarshal([]byte(b), out)
	}
	return code
}

func (e *env) apply() {
	e.t.Helper()
	if code, body := e.call("POST", "/api/config/apply", ""); code != 200 {
		e.t.Fatalf("apply = %d %s", code, body)
	}
}

func (e *env) waitFor(what string, d time.Duration, ok func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Second)
	}
}

// get requests a host through Caddy's HTTP port. It returns status -1 when
// the connection is dropped (abort).
func (e *env) get(host, path string) (int, string) {
	c := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.caddyHTTP)
		}, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest("GET", "http://"+host+path, nil)
	resp, err := c.Do(req)
	if err != nil {
		return -1, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) addHost(body string) int64 {
	e.t.Helper()
	var h struct {
		ID int64 `json:"id"`
	}
	if code := e.json("POST", "/api/hosts", body, &h); code != http.StatusCreated {
		_, b := e.call("POST", "/api/hosts", body)
		e.t.Fatalf("create host = %d %s", code, b)
	}
	return h.ID
}

// clientIP is the address Caddy sees for this test process.
func (e *env) clientIP() string {
	e.t.Helper()
	_, body := e.get("whoami.test", "/")
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "X-Forwarded-For: "); ok {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	e.t.Fatalf("no X-Forwarded-For from whoami: %s", body)
	return ""
}

func TestEndToEnd(t *testing.T) {
	e := setup(t)

	// --- proxy host over plain HTTP
	e.addHost(`{"type":"proxy","enabled":true,"domains":["whoami.test"],"tls_mode":"off","upstreams":[{"host":"whoami"}]}`)
	e.apply()
	e.waitFor("whoami.test to answer", 20*time.Second, func() bool { c, _ := e.get("whoami.test", "/"); return c == 200 })
	ip := e.clientIP()
	t.Logf("Caddy sees the test client as %s", ip)

	// --- certificate from Pebble
	e.addHost(`{"type":"proxy","enabled":true,"domains":["secure.test"],"tls_mode":"auto","force_https":true,"upstreams":[{"host":"whoami"}]}`)
	e.apply()
	if c, _ := e.get("secure.test", "/"); c != http.StatusPermanentRedirect {
		t.Fatalf("http -> https redirect = %d", c)
	}
	var issuer string
	e.waitFor("a Pebble certificate for secure.test", 120*time.Second, func() bool {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", e.caddyTLS,
			&tls.Config{ServerName: "secure.test", InsecureSkipVerify: true}) //nolint:gosec // checking who issued it
		if err != nil {
			return false
		}
		defer func() { _ = conn.Close() }()
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			return false
		}
		issuer = certs[0].Issuer.CommonName
		return strings.Contains(strings.ToLower(issuer), "pebble")
	})
	t.Logf("secure.test certificate issued by %q", issuer)

	// --- access order: deny, never-block overrides, allow-only blocks
	var pol struct {
		ID int64 `json:"id"`
	}
	if code := e.json("POST", "/api/policies", fmt.Sprintf(`{"name":"Deny test client","mode":"deny","rules":[%q]}`, ip), &pol); code != 201 {
		t.Fatalf("create policy = %d", code)
	}
	var folder struct {
		ID int64 `json:"id"`
	}
	e.json("POST", "/api/folders", fmt.Sprintf(`{"name":"Guarded","policy_ids":[%d]}`, pol.ID), &folder)
	guarded := e.addHost(fmt.Sprintf(`{"type":"proxy","enabled":true,"domains":["guarded.test"],"tls_mode":"off","upstreams":[{"host":"whoami"}],"folder_id":%d}`, folder.ID))
	e.apply()
	if c, _ := e.get("guarded.test", "/"); c != 403 {
		t.Fatalf("denied client = %d, want 403", c)
	}
	if c, _ := e.get("whoami.test", "/"); c != 200 {
		t.Fatalf("host outside the folder = %d, want 200", c)
	}
	e.call("POST", "/api/never-ban", fmt.Sprintf(`{"cidr":%q,"note":"test"}`, ip))
	e.apply()
	if c, _ := e.get("guarded.test", "/"); c != 200 {
		t.Fatalf("never-block client = %d, want 200 even though denied", c)
	}
	e.call("DELETE", "/api/never-ban?cidr="+ip, "")
	e.call("PUT", fmt.Sprintf("/api/policies/%d", pol.ID), `{"name":"Deny test client","mode":"allow_only","response":"abort","rules":["10.255.0.0/16"]}`)
	e.apply()
	if c, _ := e.get("guarded.test", "/"); c != -1 {
		t.Fatalf("client outside allow-only = %d, want a dropped connection", c)
	}
	if code, b := e.call("DELETE", fmt.Sprintf("/api/hosts/%d", guarded), ""); code != 204 {
		t.Fatalf("delete host = %d %s", code, b)
	}
	e.apply()

	// --- a config Caddy rejects leaves everything else running
	bad := e.addHost(`{"type":"proxy","enabled":true,"domains":["bad.test"],"tls_mode":"off","upstreams":[{"host":"whoami"}],
		"advanced_json":"[{\"handle\":[{\"handler\":\"no_such_handler\"}]}]"}`)
	if code, body := e.call("POST", "/api/config/apply", ""); code != http.StatusUnprocessableEntity || !strings.Contains(body, "no_such_handler") {
		t.Fatalf("broken snippet apply = %d %s", code, body)
	}
	if c, _ := e.get("whoami.test", "/"); c != 200 {
		t.Fatalf("other hosts after a rejected config = %d, want 200", c)
	}
	e.call("DELETE", fmt.Sprintf("/api/hosts/%d", bad), "")

	// --- honeypot: a trap path gets the client banned on every host
	if code, b := e.call("PUT", "/api/honeypot", `{"enabled":true,"response":"login","catchall_score":1,"threshold":10,"window_hours":24,"ban_days":7,"max_ban_days":90}`); code != 200 {
		t.Fatalf("enable honeypot = %d %s", code, b)
	}
	e.apply()
	if c, body := e.get("unknown.test", "/"); c != 200 || !strings.Contains(body, "sign in") {
		t.Fatalf("catch-all = %d %q", c, body)
	}
	start := time.Now()
	if c, _ := e.get("whoami.test", "/.env"); c != 200 {
		t.Fatalf("trap path = %d", c)
	}
	e.waitFor("the scanner to be banned", 30*time.Second, func() bool { c, _ := e.get("whoami.test", "/"); return c == -1 })
	t.Logf("banned %s after %s", ip, time.Since(start).Round(time.Second))
	if code, _ := e.call("POST", "/api/bans/unban", fmt.Sprintf(`{"cidr":%q}`, ip)); code != 200 {
		t.Fatal("unban failed")
	}
	e.waitFor("the ban to lift", 15*time.Second, func() bool { c, _ := e.get("whoami.test", "/"); return c == 200 })

	// --- the dashboard saw the traffic
	var ov struct {
		Overview struct {
			Requests int `json:"requests"`
			Blocked  int `json:"blocked"`
		} `json:"overview"`
	}
	e.waitFor("hits in the dashboard", 20*time.Second, func() bool {
		e.json("GET", "/api/stats/overview?range=1h", "", &ov)
		return ov.Overview.Requests > 5 && ov.Overview.Blocked > 0
	})

	// --- nothing pending and no drift at the end
	var preview struct {
		Pending bool `json:"pending"`
		Drift   bool `json:"drift"`
	}
	e.json("GET", "/api/config/preview", "", &preview)
	if preview.Pending || preview.Drift {
		var buf bytes.Buffer
		_, raw := e.call("GET", "/api/config/preview", "")
		buf.WriteString(raw)
		t.Fatalf("pending=%v drift=%v at the end: %.500s", preview.Pending, preview.Drift, buf.String())
	}
}
