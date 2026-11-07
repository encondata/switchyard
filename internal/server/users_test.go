package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/encondata/caddyproxymanager/internal/apply"
	"github.com/encondata/caddyproxymanager/internal/compiler"
	"github.com/encondata/caddyproxymanager/internal/secrets"
	"github.com/encondata/caddyproxymanager/internal/store"
	"github.com/encondata/caddyproxymanager/internal/totp"
)

// fullServer is a server with a secret key, signed in as an admin who has
// changed the default password. It returns the server URL for new clients.
func fullServer(t *testing.T) (*client, string) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.New(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	svc := &apply.Service{Store: st, Caddy: &fakeCaddy{running: "{}"}, Settings: compiler.Settings{AdminListen: "unix//x.sock"}}
	ts := httptest.NewServer(New(Options{Version: "test", UI: testUI(), Store: st, Apply: svc, Box: box, CaddyDataDir: t.TempDir()}))
	t.Cleanup(ts.Close)
	c := newClient(t, ts.URL)
	c.do("POST", "/api/auth/login", `{"username":"admin","password":"123456"}`)
	if code, _ := c.do("POST", "/api/auth/password", `{"current_password":"123456","new_password":"admin-passw0rd"}`); code != 200 {
		t.Fatalf("password change = %d", code)
	}
	return c, ts.URL
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, http: &http.Client{Jar: jar}}
}

func TestLoginRateLimit(t *testing.T) {
	_, base := fullServer(t)
	c := newClient(t, base)
	for i := 0; i < 5; i++ {
		if code, _ := c.do("POST", "/api/auth/login", `{"username":"admin","password":"wrong"}`); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", i, code)
		}
	}
	// Even the right password is refused while the username is locked.
	if code, body := c.do("POST", "/api/auth/login", `{"username":"admin","password":"admin-passw0rd"}`); code != http.StatusTooManyRequests {
		t.Fatalf("after 5 failures = %d %v", code, body)
	}
}

func TestTwoFactor(t *testing.T) {
	admin, base := fullServer(t)

	code, body := admin.do("POST", "/api/auth/2fa/begin", "")
	if code != 200 {
		t.Fatalf("begin = %d %v", code, body)
	}
	secret := body["secret"].(string)
	now, _ := totp.Code(secret, totp.Step(time.Now()))
	if code, _ := admin.do("POST", "/api/auth/2fa/confirm", `{"code":"000000"}`); code != 400 {
		t.Fatalf("wrong confirm code = %d", code)
	}
	code, body = admin.do("POST", "/api/auth/2fa/confirm", `{"code":"`+now+`"}`)
	codes, _ := body["backup_codes"].([]any)
	if code != 200 || len(codes) != 10 {
		t.Fatalf("confirm = %d %v", code, body)
	}

	// Signing in now needs the second step.
	c := newClient(t, base)
	code, body = c.do("POST", "/api/auth/login", `{"username":"admin","password":"admin-passw0rd"}`)
	if code != 200 || body["totp_required"] != true {
		t.Fatalf("login = %d %v", code, body)
	}
	challenge := body["challenge"].(string)
	if code, _ := c.do("GET", "/api/hosts", ""); code != http.StatusUnauthorized {
		t.Fatal("password alone gave a session")
	}
	// The code used to confirm can't be replayed.
	if code, _ := c.do("POST", "/api/auth/totp", `{"challenge":"`+challenge+`","code":"`+now+`"}`); code != http.StatusUnauthorized {
		t.Fatalf("replayed code = %d", code)
	}
	backup := codes[0].(string)
	if code, _ := c.do("POST", "/api/auth/totp", `{"challenge":"`+challenge+`","code":"`+backup+`"}`); code != 200 {
		t.Fatalf("backup code = %d", code)
	}
	if code, _ := c.do("GET", "/api/hosts", ""); code != 200 {
		t.Fatal("no session after second step")
	}
	// Backup codes are single use.
	c2 := newClient(t, base)
	_, body = c2.do("POST", "/api/auth/login", `{"username":"admin","password":"admin-passw0rd"}`)
	if code, _ := c2.do("POST", "/api/auth/totp", `{"challenge":"`+body["challenge"].(string)+`","code":"`+backup+`"}`); code != http.StatusUnauthorized {
		t.Fatalf("reused backup code = %d", code)
	}

	// Require 2FA for everyone: a new user must enroll before doing anything.
	if code, body := admin.do("PUT", "/api/settings", `{"require_2fa":true}`); code != 200 || body["require_2fa"] != true {
		t.Fatalf("require 2FA = %d %v", code, body)
	}
	if code, _ := admin.do("POST", "/api/users", `{"username":"ed","role":"editor","password":"temp-pass-123"}`); code != http.StatusCreated {
		t.Fatalf("create user = %d", code)
	}
	ed := newClient(t, base)
	ed.do("POST", "/api/auth/login", `{"username":"ed","password":"temp-pass-123"}`)
	ed.do("POST", "/api/auth/password", `{"current_password":"temp-pass-123","new_password":"ed-passw0rd-1"}`)
	if code, body := ed.do("GET", "/api/hosts", ""); code != http.StatusForbidden || body["error"] != "2fa_enrollment_required" {
		t.Fatalf("editor without 2FA = %d %v", code, body)
	}
	if code, body := ed.do("GET", "/api/auth/me", ""); code != 200 || body["must_enroll_2fa"] != true {
		t.Fatalf("me = %d %v", code, body)
	}
	if code, _ := ed.do("POST", "/api/auth/2fa/begin", ""); code != 200 {
		t.Fatalf("editor can't start enrollment: %d", code)
	}
}

func TestUserManagement(t *testing.T) {
	admin, base := fullServer(t)
	code, u := admin.do("POST", "/api/users", `{"username":"viewer1","role":"viewer","password":"temp-pass-123"}`)
	if code != http.StatusCreated || u["must_change_password"] != true {
		t.Fatalf("create = %d %v", code, u)
	}
	vid := itoa(int(u["id"].(float64)))
	if code, _ := admin.do("POST", "/api/users", `{"username":"viewer1","role":"viewer","password":"temp-pass-123"}`); code != 400 {
		t.Fatalf("duplicate username = %d", code)
	}

	v := newClient(t, base)
	v.do("POST", "/api/auth/login", `{"username":"viewer1","password":"temp-pass-123"}`)
	v.do("POST", "/api/auth/password", `{"current_password":"temp-pass-123","new_password":"viewer-passw0rd"}`)
	if code, _ := v.do("GET", "/api/hosts", ""); code != 200 {
		t.Fatal("viewer can't read hosts")
	}
	if code, _ := v.do("POST", "/api/hosts", `{"type":"404","domains":["x.localhost"],"tls_mode":"off"}`); code != http.StatusForbidden {
		t.Fatal("viewer could create a host")
	}
	if code, _ := v.do("GET", "/api/users", ""); code != http.StatusForbidden {
		t.Fatal("viewer could list users")
	}

	// Disabling signs the user out.
	if code, _ := admin.do("PUT", "/api/users/"+vid, `{"role":"viewer","disabled":true}`); code != 200 {
		t.Fatal("disable failed")
	}
	if code, _ := v.do("GET", "/api/hosts", ""); code != http.StatusUnauthorized {
		t.Fatal("disabled user still signed in")
	}

	// The last admin can't demote, disable or delete itself.
	_, me := admin.do("GET", "/api/auth/me", "")
	mid := itoa(int(me["id"].(float64)))
	if code, _ := admin.do("PUT", "/api/users/"+mid, `{"role":"viewer","disabled":false}`); code != http.StatusConflict {
		t.Fatalf("self demote = %d", code)
	}
	if code, _ := admin.do("DELETE", "/api/users/"+mid, ""); code != http.StatusConflict {
		t.Fatalf("self delete = %d", code)
	}

	if code, entries := admin.doList("GET", "/api/audit?entity=user"); code != 200 || len(entries) < 2 {
		t.Fatalf("audit = %d, %d entries", code, len(entries))
	}
}
