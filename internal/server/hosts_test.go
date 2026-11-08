package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/encondata/switchyard/internal/apply"
	"github.com/encondata/switchyard/internal/caddyadmin"
	"github.com/encondata/switchyard/internal/compiler"
	"github.com/encondata/switchyard/internal/store"
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

func TestFoldersPoliciesAPI(t *testing.T) {
	fc := &fakeCaddy{running: `{}`}
	c := signedIn(t, fc)

	code, f := c.do("POST", "/api/folders", `{"name":"Internal"}`)
	if code != http.StatusCreated {
		t.Fatalf("create folder = %d %v", code, f)
	}
	fid := itoa(int(f["id"].(float64)))

	code, p := c.do("POST", "/api/policies", `{"name":"LAN only","mode":"allow_only","rules":["10.0.0.0/8"]}`)
	if code != http.StatusCreated {
		t.Fatalf("create policy = %d %v", code, p)
	}
	pid := itoa(int(p["id"].(float64)))
	if code, body := c.do("POST", "/api/policies", `{"name":"x","mode":"deny","rules":["ZZ"]}`); code != 400 || body["fields"] == nil {
		t.Fatalf("unknown country = %d %v", code, body)
	}
	if code, body := c.do("POST", "/api/policies", `{"name":"geo","mode":"deny","rules":["us"]}`); code != http.StatusCreated {
		t.Fatalf("country rule = %d %v", code, body)
	}

	if code, _ := c.do("PUT", "/api/folders/"+fid, `{"name":"Internal","policy_ids":[`+pid+`]}`); code != 200 {
		t.Fatalf("attach policy = %d", code)
	}
	code, h := c.do("POST", "/api/hosts", `{"type":"proxy","enabled":true,"domains":["app.localhost"],
		"tls_mode":"off","upstreams":[{"host":"whoami"}],"folder_id":`+fid+`}`)
	if code != http.StatusCreated {
		t.Fatalf("create host in folder = %d %v", code, h)
	}

	// The folder's policy reaches the compiled config.
	if code, _ := c.do("POST", "/api/config/apply", ""); code != 200 || !strings.Contains(fc.running, "10.0.0.0/8") {
		t.Fatalf("apply = %d; config has policy: %v", code, strings.Contains(fc.running, "10.0.0.0/8"))
	}

	if code, body := c.do("DELETE", "/api/policies/"+pid, ""); code != http.StatusConflict {
		t.Fatalf("delete used policy = %d %v", code, body)
	}
	if code, body := c.do("DELETE", "/api/folders/"+fid, ""); code != http.StatusConflict {
		t.Fatalf("delete non-empty folder = %d %v", code, body)
	}

	if code, body := c.do("POST", "/api/folders/"+fid+"/enabled", `{"enabled":false}`); code != 200 || body["hosts_changed"].(float64) != 1 {
		t.Fatalf("disable folder = %d %v", code, body)
	}
	hid := itoa(int(h["id"].(float64)))
	if code, _ := c.do("POST", "/api/hosts/"+hid+"/move", `{"folder_id":null}`); code != 200 {
		t.Fatalf("move host = %d", code)
	}

	if code, _ := c.do("POST", "/api/never-ban", `{"cidr":"192.168.1.0/24","note":"office"}`); code != http.StatusCreated {
		t.Fatalf("add never-ban = %d", code)
	}
	if code, _ := c.do("DELETE", "/api/never-ban?cidr=192.168.1.0/24", ""); code != http.StatusNoContent {
		t.Fatalf("delete never-ban = %d", code)
	}
	if code, body := c.do("GET", "/api/whoami", ""); code != 200 || body["ip"] != "127.0.0.1" {
		t.Fatalf("whoami = %d %v", code, body)
	}
}

// The hosts list's enable switch sends a list row back as-is, read-only
// fields (certs, timestamps) included. Saving it must work.
func TestSaveHostFromListRow(t *testing.T) {
	c := signedIn(t, &fakeCaddy{running: `{}`})
	if code, body := c.do("POST", "/api/hosts", `{"type":"proxy","enabled":false,"domains":["row.example.com"],"tls_mode":"auto","upstreams":[{"host":"app"}]}`); code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, body)
	}
	code, rows := c.doList("GET", "/api/hosts")
	if code != 200 || len(rows) != 1 {
		t.Fatalf("list = %d %v", code, rows)
	}
	row := rows[0].(map[string]any)
	if _, ok := row["certs"]; !ok {
		t.Fatalf("list row has no certs field: %v", row)
	}
	row["enabled"] = true
	b, _ := json.Marshal(row)
	id := strconv.Itoa(int(row["id"].(float64)))
	if code, body := c.do("PUT", "/api/hosts/"+id, string(b)); code != 200 || body["enabled"] != true {
		t.Fatalf("save list row = %d %v", code, body)
	}
	// Unknown fields that aren't read-only host fields are still refused.
	if code, _ := c.do("PUT", "/api/hosts/"+id, `{"type":"proxy","domains":["row.example.com"],"upstreams":[{"host":"app"}],"bogus":1}`); code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", code)
	}
}
