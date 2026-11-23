// Package hslssotest is a stand-in for the HackSpaceLabs Keycloak in tests: discovery, signing keys,
// a token endpoint (authorization code with PKCE, and refresh) and sign-out, with switches to make it
// misbehave. It signs real RS256 tokens, so the code under test verifies them for real.
package hslssotest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// User is a person in the fake realm.
type User struct {
	Subject  string
	Username string
	Email    string
	Name     string
	Roles    []string // the app client's roles; nil means no hsl_roles claim, as Keycloak does
	Disabled bool
}

// Issuer is the fake Keycloak. Change its fields between steps of a test; it is safe for concurrent use.
type Issuer struct {
	URL          string // the issuer, e.g. http://127.0.0.1:1234/realms/test
	ClientID     string
	ClientSecret string
	// SessionLifetime is sent as refresh_expires_in.
	SessionLifetime time.Duration

	mu    sync.Mutex
	users map[string]*User
	codes map[string]grant
	// refresh token -> session id; sessions map session id -> subject
	refresh  map[string]string
	sessions map[string]string

	// Misbehaviour switches. Change them with Set while requests may be running.
	Down          bool // token endpoint answers 503
	WrongIssuer   bool
	WrongAudience bool
	WrongNonce    bool
	BadSignature  bool

	Server          *httptest.Server
	key, otherKey   *rsa.PrivateKey
	refreshRequests int
}

// Set changes the issuer's settings safely.
func (is *Issuer) Set(change func(*Issuer)) {
	is.mu.Lock()
	defer is.mu.Unlock()
	change(is)
}

// RefreshRequests counts refresh-token requests so far.
func (is *Issuer) RefreshRequests() int {
	is.mu.Lock()
	defer is.mu.Unlock()
	return is.refreshRequests
}

type grant struct {
	subject, nonce, challenge, redirect, sid string
}

// New starts a fake issuer for one client.
func New(t *testing.T, clientID, clientSecret string) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &Issuer{
		ClientID: clientID, ClientSecret: clientSecret, SessionLifetime: 96 * time.Hour,
		users: map[string]*User{}, codes: map[string]grant{}, refresh: map[string]string{}, sessions: map[string]string{},
		key: key, otherKey: other,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /realms/test/.well-known/openid-configuration", is.discovery)
	mux.HandleFunc("GET /realms/test/protocol/openid-connect/certs", is.certs)
	mux.HandleFunc("POST /realms/test/protocol/openid-connect/token", is.token)
	is.Server = httptest.NewServer(mux)
	t.Cleanup(is.Server.Close)
	is.URL = is.Server.URL + "/realms/test"
	return is
}

// AddUser adds or replaces a user.
func (is *Issuer) AddUser(u User) {
	is.mu.Lock()
	defer is.mu.Unlock()
	cp := u
	is.users[u.Subject] = &cp
}

// Update changes a user in place.
func (is *Issuer) Update(subject string, change func(*User)) {
	is.mu.Lock()
	defer is.mu.Unlock()
	change(is.users[subject])
}

// SignOut ends every Keycloak session of a user (as signing out in any app does).
func (is *Issuer) SignOut(subject string) {
	is.mu.Lock()
	defer is.mu.Unlock()
	for sid, sub := range is.sessions {
		if sub == subject {
			delete(is.sessions, sid)
		}
	}
}

// Authorize plays the browser and Keycloak's sign-in form: given the address the app redirected to,
// it checks it and returns the app callback address with a code, signing in as subject.
func (is *Issuer) Authorize(t *testing.T, authURL, subject string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != is.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatalf("bad authorization request: %s", authURL)
	}
	code := randomString()
	sid := randomString()
	is.mu.Lock()
	is.codes[code] = grant{subject: subject, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"),
		redirect: q.Get("redirect_uri"), sid: sid}
	is.sessions[sid] = subject
	is.mu.Unlock()
	back, _ := url.Parse(q.Get("redirect_uri"))
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	return back.String()
}

func (is *Issuer) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                           is.URL,
		"authorization_endpoint":           is.URL + "/protocol/openid-connect/auth",
		"token_endpoint":                   is.URL + "/protocol/openid-connect/token",
		"jwks_uri":                         is.URL + "/protocol/openid-connect/certs",
		"end_session_endpoint":             is.URL + "/protocol/openid-connect/logout",
		"code_challenge_methods_supported": []string{"plain", "S256"},
	})
}

func (is *Issuer) certs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &is.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
	}})
}

func (is *Issuer) token(w http.ResponseWriter, r *http.Request) {
	is.mu.Lock()
	defer is.mu.Unlock()
	if is.Down {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != is.ClientID || secret != is.ClientSecret {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	var sub, sid, nonce string
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		g, ok := is.codes[r.PostFormValue("code")]
		delete(is.codes, r.PostFormValue("code"))
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if !ok || g.redirect != r.PostFormValue("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		sub, sid, nonce = g.subject, g.sid, g.nonce
	case "refresh_token":
		is.refreshRequests++
		sid = is.refresh[r.PostFormValue("refresh_token")]
		sub = is.sessions[sid]
		if sid == "" || sub == "" {
			oauthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	u := is.users[sub]
	if u == nil || u.Disabled {
		delete(is.sessions, sid)
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": is.URL, "aud": is.ClientID, "azp": is.ClientID, "sub": sub, "sid": sid, "typ": "ID",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(),
		"preferred_username": u.Username, "email": u.Email, "email_verified": false, "name": u.Name,
	}
	if u.Roles != nil {
		claims["hsl_roles"] = u.Roles
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if is.WrongIssuer {
		claims["iss"] = is.URL + "-other"
	}
	if is.WrongAudience {
		claims["aud"], claims["azp"] = "someone-else", "someone-else"
	}
	if is.WrongNonce && nonce != "" {
		claims["nonce"] = "not-the-nonce"
	}
	signWith := is.key
	if is.BadSignature {
		signWith = is.otherKey
	}
	idToken := sign(signWith, claims)
	rt := randomString()
	is.refresh[rt] = sid
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": randomString(), "token_type": "Bearer", "expires_in": 300,
		"refresh_token": rt, "refresh_expires_in": int(is.SessionLifetime.Seconds()), "id_token": idToken,
	})
}

func sign(key *rsa.PrivateKey, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		panic(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
