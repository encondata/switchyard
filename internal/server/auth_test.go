package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encondata/caddyproxymanager/internal/store"
)

type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func newTestServer(t *testing.T) *client {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(Options{Version: "test", UI: testUI(), Store: st}))
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: ts.URL, http: &http.Client{Jar: jar}}
}

// do sends a request and returns the status and decoded JSON body.
func (c *client) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestFirstLoginForcesPasswordChange(t *testing.T) {
	c := newTestServer(t)

	if code, _ := c.do("GET", "/api/status", ""); code != http.StatusUnauthorized {
		t.Fatalf("status before login = %d, want 401", code)
	}
	if code, _ := c.do("POST", "/api/auth/login", `{"username":"admin","password":"nope"}`); code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d, want 401", code)
	}

	code, me := c.do("POST", "/api/auth/login", `{"username":"admin","password":"123456"}`)
	if code != http.StatusOK || me["must_change_password"] != true {
		t.Fatalf("login = %d %v, want 200 with must_change_password", code, me)
	}

	// Everything except me/password/logout is blocked until the change.
	if code, body := c.do("GET", "/api/status", ""); code != http.StatusForbidden || body["error"] != "password_change_required" {
		t.Fatalf("status with pending change = %d %v, want 403 password_change_required", code, body)
	}
	if code, _ := c.do("GET", "/api/auth/me", ""); code != http.StatusOK {
		t.Fatalf("me = %d, want 200", code)
	}

	for _, bad := range []string{
		`{"current_password":"123456","new_password":"short"}`,
		`{"current_password":"123456","new_password":"123456"}`,
		`{"current_password":"wrong-one","new_password":"a-good-passw0rd"}`,
	} {
		if code, _ := c.do("POST", "/api/auth/password", bad); code != http.StatusBadRequest {
			t.Errorf("password change %s = %d, want 400", bad, code)
		}
	}

	code, me = c.do("POST", "/api/auth/password", `{"current_password":"123456","new_password":"a-good-passw0rd"}`)
	if code != http.StatusOK || me["must_change_password"] != false {
		t.Fatalf("password change = %d %v", code, me)
	}
	if code, _ := c.do("GET", "/api/status", ""); code != http.StatusOK {
		t.Fatalf("status after change = %d, want 200", code)
	}

	// Sign out, then the old password fails and the new one works without a prompt.
	if code, _ := c.do("POST", "/api/auth/logout", ""); code != http.StatusNoContent {
		t.Fatalf("logout = %d", code)
	}
	if code, _ := c.do("GET", "/api/auth/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("me after logout = %d, want 401", code)
	}
	if code, _ := c.do("POST", "/api/auth/login", `{"username":"admin","password":"123456"}`); code != http.StatusUnauthorized {
		t.Fatalf("old password login = %d, want 401", code)
	}
	code, me = c.do("POST", "/api/auth/login", `{"username":"admin","password":"a-good-passw0rd"}`)
	if code != http.StatusOK || me["must_change_password"] != false {
		t.Fatalf("new password login = %d %v", code, me)
	}
}

func TestLoginRequiresJSON(t *testing.T) {
	c := newTestServer(t)
	resp, err := c.http.Post(c.base+"/api/auth/login", "application/x-www-form-urlencoded",
		strings.NewReader("username=admin&password=123456"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("form login = %d, want 415", resp.StatusCode)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	c := newTestServer(t)
	req, _ := http.NewRequest("POST", c.base+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	var ck *http.Cookie
	for _, k := range resp.Cookies() {
		if k.Name == sessionCookie {
			ck = k
		}
	}
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v, want HttpOnly and SameSite=Strict", ck)
	}
}
