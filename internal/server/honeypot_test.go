package server

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/encondata/switchyard/internal/apply"
	"github.com/encondata/switchyard/internal/compiler"
	"github.com/encondata/switchyard/internal/hits"
	"github.com/encondata/switchyard/internal/store"
)

// Saving honeypot settings without the abuse section (as clients older
// than it do) keeps the abuse settings instead of failing validation.
func TestHoneypotSaveKeepsOmittedFields(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	hdb, err := hits.Open(ctx, filepath.Join(t.TempDir(), "hits.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hdb.Close() })
	if _, err := st.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	svc := &apply.Service{Store: st, Caddy: &fakeCaddy{running: `{}`}, Settings: compiler.Settings{AdminListen: "unix//x.sock"}}
	ts := httptest.NewServer(New(Options{Version: "test", UI: testUI(), Store: st, Apply: svc, Hits: hdb, CaddyDataDir: t.TempDir()}))
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ts.URL, http: &http.Client{Jar: jar}}
	c.do("POST", "/api/auth/login", `{"username":"admin","password":"123456"}`)
	c.do("POST", "/api/auth/password", `{"current_password":"123456","new_password":"a-good-passw0rd"}`)

	code, body := c.do("PUT", "/api/honeypot", `{"enabled":true,"response":"login","catchall_score":2,"threshold":10,"window_hours":24,"ban_days":7,"max_ban_days":90}`)
	if code != 200 {
		t.Fatalf("save without abuse = %d %v", code, body)
	}
	abuse, _ := body["abuse"].(map[string]any)
	if body["catchall_score"] != float64(2) || abuse["enabled"] != true || abuse["window_minutes"] != float64(5) {
		t.Errorf("saved = %v", body)
	}
}
