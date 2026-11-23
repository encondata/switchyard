package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/encondata/switchyard/internal/hslsso"
	"github.com/encondata/switchyard/internal/hslsso/hslssotest"
	"github.com/encondata/switchyard/internal/secrets"
	"github.com/encondata/switchyard/internal/store"
)

type ssoEnv struct {
	t      *testing.T
	base   string
	issuer *hslssotest.Issuer
	store  *store.Store
	http   *http.Client // keeps cookies, does not follow redirects
}

// newSSOServer starts Switchyard with Sign in with HackSpaceLabs pointed at a fake Keycloak.
func newSSOServer(t *testing.T, recheck time.Duration) *ssoEnv {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, err := secrets.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	issuer := hslssotest.New(t, "switchyard", "client-secret")
	var handler http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	client, err := hslsso.New(hslsso.Config{Issuer: issuer.URL, ClientID: "switchyard", ClientSecret: "client-secret",
		RedirectURL: ts.URL + "/api/auth/oidc/callback"})
	if err != nil {
		t.Fatal(err)
	}
	handler = New(Options{Version: "test", UI: testUI(), Store: st, Box: box, SSO: SSOOptions{
		Client: client, PublicURL: ts.URL, RecheckEvery: recheck, PortalURL: "http://portal.test",
		Apps: []SuiteApp{{ID: "switchyard", Name: "Switchyard", URL: ts.URL}},
	}})
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	issuer.AddUser(hslssotest.User{Subject: "sub-alice", Username: "alice", Email: "alice@example.com", Name: "Alice Example", Roles: []string{"editor"}})
	return &ssoEnv{t: t, base: ts.URL, issuer: issuer, store: st, http: hc}
}

// result is what the tests look at in a response (its body is already read and closed).
type result struct {
	StatusCode int
	Header     http.Header
	cookies    []*http.Cookie
}

func (r result) Cookies() []*http.Cookie { return r.cookies }

func done(resp *http.Response) result {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return result{StatusCode: resp.StatusCode, Header: resp.Header, cookies: resp.Cookies()}
}

func (e *ssoEnv) get(path string) result {
	e.t.Helper()
	target := path
	if strings.HasPrefix(path, "/") {
		target = e.base + path
	}
	resp, err := e.http.Get(target)
	if err != nil {
		e.t.Fatal(err)
	}
	return done(resp)
}

func (e *ssoEnv) post(path, body string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.base+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *ssoEnv) me() (int, map[string]any) {
	e.t.Helper()
	resp, err := e.http.Get(e.base + "/api/auth/me")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// start begins a sign-in and returns the Keycloak address it redirected to.
func (e *ssoEnv) start(next string) string {
	e.t.Helper()
	resp := e.get("/api/auth/oidc/login?next=" + url.QueryEscape(next))
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), e.issuer.URL) {
		e.t.Fatalf("start: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	return resp.Header.Get("Location")
}

// signIn runs the whole flow as subject and returns the callback's response.
func (e *ssoEnv) signIn(subject, next string) result {
	e.t.Helper()
	return e.get(e.issuer.Authorize(e.t, e.start(next), subject))
}

func wantRedirect(t *testing.T, resp result, want string) {
	t.Helper()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != want {
		t.Fatalf("got %d -> %q, want 303 -> %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
}

func TestSSOSignIn(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	resp := e.signIn("sub-alice", "/#/hosts/3")
	wantRedirect(t, resp, "/#/hosts/3")
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil || session.MaxAge != 96*3600 || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie: %+v", session)
	}
	status, me := e.me()
	if status != http.StatusOK || me["username"] != "alice" || me["role"] != "editor" || me["auth_source"] != "oidc" ||
		me["display_name"] != "Alice Example" {
		t.Fatalf("me: %d %v", status, me)
	}
	// Signing in again finds the same account.
	e.signIn("sub-alice", "/")
	users, _ := e.store.ListUsers(context.Background())
	if len(users) != 2 {
		t.Fatalf("want admin + alice, got %d users", len(users))
	}
}

func TestSSORememberMeLifetime(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	e.issuer.Set(func(is *hslssotest.Issuer) { is.SessionLifetime = 30 * 24 * time.Hour })
	resp := e.signIn("sub-alice", "/")
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			found = true
			if c.MaxAge != 30*24*3600 {
				t.Fatalf("cookie MaxAge %d, want 30 days", c.MaxAge)
			}
		}
	}
	if !found {
		t.Fatal("no session cookie")
	}
}

// Turning HackSpaceLabs sign-in off ends its sessions instead of leaving them unchecked.
func TestSSOSessionsEndWhenSignInIsTurnedOff(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	e.signIn("sub-alice", "/")
	off := httptest.NewServer(New(Options{Version: "test", UI: testUI(), Store: e.store}))
	t.Cleanup(off.Close)
	u, _ := url.Parse(e.base)
	req, _ := http.NewRequest(http.MethodGet, off.URL+"/api/auth/me", nil)
	for _, c := range e.http.Jar.Cookies(u) {
		req.AddCookie(c)
	}
	raw, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp := done(raw); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session survived with sign-in off: %d", resp.StatusCode)
	}
}

func TestSSOCallbackNeedsItsOwnFlow(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	callback := e.issuer.Authorize(t, e.start("/"), "sub-alice")

	// Another browser (no flow cookie) can't use the callback address.
	other := *e
	jar, _ := cookiejar.New(nil)
	other.http = &http.Client{Jar: jar, CheckRedirect: e.http.CheckRedirect}
	wantRedirect(t, other.get(callback), "/login?error=sso_expired")

	// Tampered state.
	u, _ := url.Parse(callback)
	q := u.Query()
	q.Set("state", "not-the-state")
	u.RawQuery = q.Encode()
	wantRedirect(t, e.get(u.String()), "/login?error=sso_expired")

	// The real one works once.
	wantRedirect(t, e.get(callback), "/")
	// Replaying it: the flow is gone; this browser is already signed in, so it just goes home.
	wantRedirect(t, e.get(callback), "/")
	other.http.Jar, _ = cookiejar.New(nil)
	wantRedirect(t, other.get(callback), "/login?error=sso_expired")
}

func TestSSORejectsBadTokens(t *testing.T) {
	for name, set := range map[string]func(*hslssotest.Issuer){
		"issuer":    func(is *hslssotest.Issuer) { is.WrongIssuer = true },
		"audience":  func(is *hslssotest.Issuer) { is.WrongAudience = true },
		"nonce":     func(is *hslssotest.Issuer) { is.WrongNonce = true },
		"signature": func(is *hslssotest.Issuer) { is.BadSignature = true },
	} {
		t.Run(name, func(t *testing.T) {
			e := newSSOServer(t, time.Minute)
			e.issuer.Set(set)
			wantRedirect(t, e.signIn("sub-alice", "/"), "/login?error=sso_failed")
			if status, _ := e.me(); status != http.StatusUnauthorized {
				t.Fatalf("signed in anyway: %d", status)
			}
		})
	}
}

func TestSSONoRoleNoAccount(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	e.issuer.AddUser(hslssotest.User{Subject: "sub-cust", Username: "customer"}) // no hsl_roles claim at all
	e.issuer.AddUser(hslssotest.User{Subject: "sub-other", Username: "other", Roles: []string{"portal-admin"}})
	wantRedirect(t, e.signIn("sub-cust", "/"), "/login?error=no_access")
	wantRedirect(t, e.signIn("sub-other", "/"), "/login?error=no_access")
	users, _ := e.store.ListUsers(context.Background())
	if len(users) != 1 {
		t.Fatalf("accounts were created: %d", len(users))
	}
}

func TestSSOUsernameClashesAndRules(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	// "admin" is the local default account: no linking, refused.
	e.issuer.AddUser(hslssotest.User{Subject: "sub-admin", Username: "Admin", Roles: []string{"admin"}})
	wantRedirect(t, e.signIn("sub-admin", "/"), "/login?error=account_exists")
	// Same name as an existing HackSpaceLabs account, but a different Keycloak user.
	e.signIn("sub-alice", "/")
	e.issuer.AddUser(hslssotest.User{Subject: "sub-alice-2", Username: "alice", Roles: []string{"viewer"}})
	e.http.Jar, _ = cookiejar.New(nil)
	wantRedirect(t, e.signIn("sub-alice-2", "/"), "/login?error=account_exists")
	// A username Switchyard can't hold.
	e.issuer.AddUser(hslssotest.User{Subject: "sub-x", Username: "a b", Roles: []string{"viewer"}})
	wantRedirect(t, e.signIn("sub-x", "/"), "/login?error=username_invalid")
}

func TestSSOAccountHasNoPassword(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	e.signIn("sub-alice", "/")
	e.http.Jar, _ = cookiejar.New(nil)
	if status, out := e.post("/api/auth/login", `{"username":"alice","password":"!hackspacelabs"}`); status != http.StatusUnauthorized {
		t.Fatalf("password sign-in: %d %v", status, out)
	}
	users, _ := e.store.ListUsers(context.Background())
	for _, u := range users {
		if u.Username == "alice" {
			if err := e.store.ResetPassword(context.Background(), u.ID, "a-new-password", "admin"); err == nil {
				t.Fatal("reset password on a HackSpaceLabs account")
			}
		}
	}
}

func TestSSORecheck(t *testing.T) {
	e := newSSOServer(t, 10*time.Millisecond)
	e.signIn("sub-alice", "/")
	wait := func() { time.Sleep(20 * time.Millisecond) }

	// Role change comes through.
	e.issuer.Update("sub-alice", func(u *hslssotest.User) { u.Roles = []string{"viewer"} })
	wait()
	if _, me := e.me(); me["role"] != "viewer" {
		t.Fatalf("role after recheck: %v", me["role"])
	}

	// Keycloak down: the session stays.
	e.issuer.Set(func(is *hslssotest.Issuer) { is.Down = true })
	wait()
	if status, _ := e.me(); status != http.StatusOK {
		t.Fatalf("outage ended the session: %d", status)
	}
	e.issuer.Set(func(is *hslssotest.Issuer) { is.Down = false })

	// Role removed: the session ends.
	e.issuer.Update("sub-alice", func(u *hslssotest.User) { u.Roles = nil })
	wait()
	if status, _ := e.me(); status != http.StatusUnauthorized {
		t.Fatalf("no role, still signed in: %d", status)
	}
}

func TestSSORecheckSignedOutOrDisabled(t *testing.T) {
	for name, act := range map[string]func(*hslssotest.Issuer){
		"signed out": func(is *hslssotest.Issuer) { is.SignOut("sub-alice") },
		"disabled":   func(is *hslssotest.Issuer) { is.Update("sub-alice", func(u *hslssotest.User) { u.Disabled = true }) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newSSOServer(t, 10*time.Millisecond)
			e.signIn("sub-alice", "/")
			act(e.issuer)
			time.Sleep(20 * time.Millisecond)
			if status, _ := e.me(); status != http.StatusUnauthorized {
				t.Fatalf("still signed in: %d", status)
			}
		})
	}
}

func TestSSORecheckWaitsForItsInterval(t *testing.T) {
	e := newSSOServer(t, time.Hour)
	e.signIn("sub-alice", "/")
	e.issuer.SignOut("sub-alice")
	for range 3 {
		if status, _ := e.me(); status != http.StatusOK {
			t.Fatalf("rechecked before the interval: %d", status)
		}
	}
	if n := e.issuer.RefreshRequests(); n != 0 {
		t.Fatalf("%d refreshes before the interval", n)
	}
}

func TestSSOLastAdminIsNotDemotedButSignedOut(t *testing.T) {
	e := newSSOServer(t, 10*time.Millisecond)
	e.issuer.Update("sub-alice", func(u *hslssotest.User) { u.Roles = []string{"admin", "viewer"} })
	e.signIn("sub-alice", "/")
	if _, me := e.me(); me["role"] != "admin" {
		t.Fatalf("highest role not used: %v", me["role"])
	}
	// Make alice the only enabled admin.
	users, _ := e.store.ListUsers(context.Background())
	for _, u := range users {
		if u.Username == "admin" {
			if _, err := e.store.UpdateUser(context.Background(), u.ID, "admin", true, "test"); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.issuer.Update("sub-alice", func(u *hslssotest.User) { u.Roles = []string{"viewer"} })
	time.Sleep(20 * time.Millisecond)
	if status, _ := e.me(); status != http.StatusUnauthorized {
		t.Fatalf("demotion refused but still signed in: %d", status)
	}
	if u, _ := e.store.GetUser(context.Background(), users[1].ID); u.Username == "alice" && u.Role != "admin" {
		t.Fatalf("last admin was demoted: %v", u.Role)
	}
}

func TestSSOLocalStepsDontApply(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	if err := e.store.SetSetting(context.Background(), store.SettingRequire2FA, "true", "test"); err != nil {
		t.Fatal(err)
	}
	e.issuer.Update("sub-alice", func(u *hslssotest.User) { u.Roles = []string{"admin"} })
	e.signIn("sub-alice", "/")
	_, me := e.me()
	if me["must_enroll_2fa"] != false || me["must_change_password"] != false {
		t.Fatalf("local steps shown: %v", me)
	}
	resp := e.get("/api/users")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("required 2FA blocked a HackSpaceLabs session: %d", resp.StatusCode)
	}
}

func TestSSOSignOut(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	e.signIn("sub-alice", "/")
	status, out := e.post("/api/auth/logout", "")
	if status != http.StatusOK {
		t.Fatalf("logout: %d", status)
	}
	target, _ := url.Parse(out["redirect"].(string))
	q := target.Query()
	if !strings.HasPrefix(out["redirect"].(string), e.issuer.URL+"/protocol/openid-connect/logout?") ||
		q.Get("client_id") != "switchyard" || q.Get("id_token_hint") == "" || q.Get("post_logout_redirect_uri") != e.base+"/signed-out" {
		t.Fatalf("redirect: %v", out["redirect"])
	}
	if status, _ := e.me(); status != http.StatusUnauthorized {
		t.Fatalf("still signed in: %d", status)
	}
	// A local session still gets 204.
	if status, _ := e.post("/api/auth/login", `{"username":"admin","password":"123456"}`); status != http.StatusOK {
		t.Fatalf("local login: %d", status)
	}
	if status, _ := e.post("/api/auth/logout", ""); status != http.StatusNoContent {
		t.Fatalf("local logout: %d", status)
	}
}

func TestSSOHostAndNext(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	// Reached by another name: go to the public address first, keeping the query.
	u, _ := url.Parse(e.base)
	req, _ := http.NewRequest(http.MethodGet, e.base+"/api/auth/oidc/login?next=%2Fx", nil)
	req.Host = "localhost:" + u.Port()
	raw, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	wantRedirect(t, done(raw), e.base+"/api/auth/oidc/login?next=%2Fx")
	// An outside address in next is ignored.
	for _, bad := range []string{"https://evil.example/", "//evil.example", "/\\evil", "/\tx"} {
		wantRedirect(t, e.signIn("sub-alice", bad), "/")
	}
}

func TestSSOConfigAndOff(t *testing.T) {
	e := newSSOServer(t, time.Minute)
	resp, _ := e.http.Get(e.base + "/api/auth/config")
	var cfg map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&cfg)
	_ = resp.Body.Close()
	if cfg["oidc"].(map[string]any)["enabled"] != true || cfg["portal_url"] != "http://portal.test" || len(cfg["apps"].([]any)) != 1 {
		t.Fatalf("config: %v", cfg)
	}

	c := newTestServer(t) // no SSO
	if status, out := c.do("GET", "/api/auth/config", ""); status != 200 || out["oidc"].(map[string]any)["enabled"] != false {
		t.Fatalf("config without SSO: %d %v", status, out)
	}
	if status, _ := c.do("GET", "/api/auth/oidc/login", ""); status != http.StatusNotFound {
		t.Fatalf("login without SSO: %d", status)
	}
}

func TestLocalSessionLasts96Hours(t *testing.T) {
	c := newTestServer(t)
	req, _ := http.NewRequest(http.MethodPost, c.base+"/api/auth/login", strings.NewReader(`{"username":"admin","password":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	raw, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp := done(raw)
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie && ck.MaxAge != 96*3600 {
			t.Fatalf("MaxAge %d", ck.MaxAge)
		}
	}
}
