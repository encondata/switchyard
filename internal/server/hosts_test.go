package server

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/encondata/caddyproxymanager/internal/apply"
	"github.com/encondata/caddyproxymanager/internal/caddyadmin"
	"github.com/encondata/caddyproxymanager/internal/compiler"
	"github.com/encondata/caddyproxymanager/internal/store"
)

type fakeCaddy struct {
	running string
	reject  bool
}

func (f *fakeCaddy) Config(context.Context) ([]byte, error) { return []byte(f.running), nil }
func (f *fakeCaddy) Load(_ context.Context, b []byte) error {
	if f.reject {
		return &caddyadmin.LoadError{Status: 400, Message: "bad config"}
	}
	f.running = string(b)
	return nil
}

// signedIn returns a client signed in as an admin who has already changed
// the default password.
func signedIn(t *testing.T, fc *fakeCaddy) *client {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := &apply.Service{Store: st, Caddy: fc, Settings: compiler.Settings{AdminListen: "unix//x.sock"}}
	ts := httptest.NewServer(New(Options{Version: "test", UI: testUI(), Store: st, Apply: svc, CaddyDataDir: t.TempDir()}))
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ts.URL, http: &http.Client{Jar: jar}}
	c.do("POST", "/api/auth/login", `{"username":"admin","password":"123456"}`)
	if code, _ := c.do("POST", "/api/auth/password", `{"current_password":"123456","new_password":"a-good-passw0rd"}`); code != 200 {
		t.Fatalf("password change = %d", code)
	}
	return c
}

func TestHostsAndApply(t *testing.T) {
	fc := &fakeCaddy{running: `{}`}
	c := signedIn(t, fc)

	code, body := c.do("POST", "/api/hosts", `{"type":"proxy","enabled":true,"domains":["app.localhost"],
		"tls_mode":"off","upstreams":[{"host":"whoami","port":80}]}`)
	if code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, body)
	}
	id := int(body["id"].(float64))

	code, body = c.do("POST", "/api/hosts", `{"type":"proxy","domains":["bad domain"],"upstreams":[]}`)
	fields, _ := body["fields"].(map[string]any)
	if code != http.StatusBadRequest || fields["domains"] == nil || fields["upstreams"] == nil {
		t.Fatalf("invalid create = %d %v", code, body)
	}

	code, body = c.do("GET", "/api/config/preview", "")
	if code != 200 || body["pending"] != true || !strings.Contains(body["diff"].(string), "app.localhost") {
		t.Fatalf("preview = %d %v", code, body)
	}

	code, body = c.do("POST", "/api/config/apply", "")
	if code != 200 || body["result"] != "ok" || !strings.Contains(fc.running, "app.localhost") {
		t.Fatalf("apply = %d %v", code, body)
	}
	if _, body = c.do("GET", "/api/config/preview", ""); body["pending"] != false {
		t.Fatalf("still pending after apply: %v", body)
	}

	fc.reject = true
	c.do("PUT", "/api/hosts/"+itoa(id), `{"type":"404","enabled":true,"domains":["app.localhost"],"tls_mode":"off"}`)
	code, body = c.do("POST", "/api/config/apply", "")
	if code != http.StatusUnprocessableEntity || body["error"] != "caddy_rejected" || body["message"] != "bad config" {
		t.Fatalf("rejected apply = %d %v", code, body)
	}

	if code, _ := c.do("DELETE", "/api/hosts/"+itoa(id), ""); code != http.StatusNoContent {
		t.Fatalf("delete = %d", code)
	}
	if code, _ := c.do("GET", "/api/hosts/"+itoa(id), ""); code != http.StatusNotFound {
		t.Fatalf("get deleted = %d", code)
	}
}

func TestHostsNeedSignIn(t *testing.T) {
	c := newTestServer(t)
	if code, _ := c.do("GET", "/api/hosts", ""); code != http.StatusNotFound && code != http.StatusUnauthorized {
		t.Fatalf("hosts without sign-in = %d", code)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
