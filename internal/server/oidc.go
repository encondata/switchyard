package server

// Sign in with HackSpaceLabs (Keycloak OpenID Connect). The contract is PLAN.md section 5 in
// encondata/hsl-suite: sign-in starts at /api/auth/oidc/login, comes back to /api/auth/oidc/callback,
// and makes an ordinary Switchyard session whose length follows Keycloak's session. That session is
// rechecked with Keycloak at most every RecheckEvery; a definite "no" (signed out, disabled, no role)
// ends it, an unreachable Keycloak does not.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/encondata/switchyard/internal/hslsso"
	"github.com/encondata/switchyard/internal/store"
)

// SSOOptions configures Sign in with HackSpaceLabs.
type SSOOptions struct {
	// Client is nil when HackSpaceLabs sign-in isn't configured.
	Client *hslsso.Client
	// PublicURL is the address people use for Switchyard, without a trailing slash.
	PublicURL string
	// AutoRedirect sends signed-out visitors straight to Keycloak.
	AutoRedirect bool
	// RecheckEvery is how often a session is rechecked with Keycloak (default one minute).
	RecheckEvery time.Duration
	// PortalURL and Apps feed the app switcher and the "Profile" link.
	PortalURL string
	Apps      []SuiteApp
}

// SuiteApp is one entry in the HackSpaceLabs app switcher.
type SuiteApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// The roles Switchyard knows, highest first.
var ssoRoles = []string{"admin", "editor", "viewer"}

const sealPurpose = "hsl-session-tokens"

type sealedTokens struct {
	Subject      string `json:"sub"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func (s *srv) ssoEnabled() bool { return s.sso.Client != nil }

func (s *srv) handleAuthConfig(w http.ResponseWriter, _ *http.Request) {
	apps := s.sso.Apps
	if apps == nil {
		apps = []SuiteApp{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"oidc":       map[string]bool{"enabled": s.ssoEnabled(), "auto_redirect": s.ssoEnabled() && s.sso.AutoRedirect},
		"portal_url": s.sso.PortalURL,
		"apps":       apps,
	})
}

// flowCookie names the cookie that binds one sign-in attempt to the browser. Each attempt gets its own,
// so several tabs signing in at once don't overwrite each other.
func flowCookie(state string) string {
	sum := sha256.Sum256([]byte(state))
	return "cpm_oidc_" + hex.EncodeToString(sum[:4])
}

const flowCookiePath = "/api/auth/oidc/"

func (s *srv) loginRedirect(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(code), http.StatusSeeOther)
}

func (s *srv) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !s.ssoEnabled() {
		writeError(w, http.StatusNotFound, "sso_off", "HackSpaceLabs sign-in isn't set up on this server.")
		return
	}
	// The flow cookie must be set on the host Keycloak sends the browser back to. Compare host names
	// only: cookies ignore ports, and a proxy may drop the port from Host.
	if pu, err := url.Parse(s.sso.PublicURL); err == nil && hostOnly(r.Host) != pu.Hostname() {
		//nolint:gosec // G710: the target is the configured public URL; only the path and query come from the request.
		http.Redirect(w, r, s.sso.PublicURL+r.URL.RequestURI(), http.StatusSeeOther)
		return
	}
	q := r.URL.Query()
	next := hslsso.SafeNext(q.Get("next"))
	prompt := ""
	if q.Get("prompt") == "login" {
		prompt = "login"
	}
	flow, err := hslsso.NewFlow()
	if err != nil {
		s.internalError(w, err)
		return
	}
	target, err := s.sso.Client.AuthURL(r.Context(), flow, prompt)
	if err != nil {
		s.log.Warn("HackSpaceLabs sign-in unavailable", "err", err)
		s.loginRedirect(w, r, "sso_unavailable")
		return
	}
	if err := s.store.SaveOIDCFlow(r.Context(), flow.State, flow.Nonce, flow.Verifier, next); err != nil {
		s.internalError(w, err)
		return
	}
	//nolint:gosec // Secure is set from CPM_SECURE_COOKIES; off for plain-HTTP LAN access.
	http.SetCookie(w, &http.Cookie{
		Name: flowCookie(flow.State), Value: flow.State, Path: flowCookiePath, MaxAge: 600,
		HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

func (s *srv) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !s.ssoEnabled() {
		writeError(w, http.StatusNotFound, "sso_off", "HackSpaceLabs sign-in isn't set up on this server.")
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	var bound bool
	if c, err := r.Cookie(flowCookie(state)); err == nil && state != "" {
		bound = subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) == 1
		//nolint:gosec // see handleOIDCLogin
		http.SetCookie(w, &http.Cookie{Name: c.Name, Value: "", Path: flowCookiePath, MaxAge: -1,
			HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteLaxMode})
	}
	var nonce, verifier, next string
	err := store.ErrNotFound
	if bound {
		nonce, verifier, next, err = s.store.TakeOIDCFlow(r.Context(), state)
	}
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, err)
			return
		}
		// Another tab may have finished signing in already.
		if s.hasSession(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		s.loginRedirect(w, r, "sso_expired")
		return
	}
	if e := q.Get("error"); e != "" {
		code := "sso_failed"
		if e == "access_denied" {
			code = "sso_cancelled"
		}
		s.loginRedirect(w, r, code)
		return
	}
	tokens, err := s.sso.Client.Exchange(r.Context(), q.Get("code"), hslsso.Flow{State: state, Nonce: nonce, Verifier: verifier})
	if err != nil {
		s.log.Warn("HackSpaceLabs sign-in failed", "err", err)
		code := "sso_failed"
		if errors.Is(err, hslsso.ErrUnavailable) {
			code = "sso_unavailable"
		}
		s.loginRedirect(w, r, code)
		return
	}
	cl := tokens.Claims
	roles := hslsso.KnownRoles(cl.Roles, ssoRoles...)
	if len(roles) == 0 {
		s.refuse(r, cl.PreferredUsername, "no Switchyard role")
		s.loginRedirect(w, r, "no_access")
		return
	}
	u, err := s.store.OIDCUser(r.Context(), cl.Subject, cl.PreferredUsername, cl.Name, cl.Email, roles[0])
	var conflict store.ConflictError
	switch {
	case errors.Is(err, store.ErrAccountExists):
		s.refuse(r, cl.PreferredUsername, "a different account already has this username")
		s.loginRedirect(w, r, "account_exists")
		return
	case errors.Is(err, store.ErrUsernameInvalid):
		s.refuse(r, cl.PreferredUsername, "username doesn't fit Switchyard's rules")
		s.loginRedirect(w, r, "username_invalid")
		return
	case errors.Is(err, store.ErrAccountDisabled):
		s.refuse(r, cl.PreferredUsername, "account disabled in Switchyard")
		s.loginRedirect(w, r, "no_access")
		return
	case errors.As(err, &conflict):
		s.refuse(r, cl.PreferredUsername, string(conflict))
		s.loginRedirect(w, r, "no_access")
		return
	case err != nil:
		s.internalError(w, err)
		return
	}
	sealed, err := s.sealTokens(cl.Subject, tokens)
	if err != nil {
		s.internalError(w, err)
		return
	}
	ttl := sessionLifetime(tokens)
	token, err := s.store.CreateOIDCSession(r.Context(), u.ID, ttl, cl.SessionID, sealed)
	if err != nil {
		s.internalError(w, err)
		return
	}
	s.setSessionCookie(w, token, ttl)
	s.log.Info("signed in with HackSpaceLabs", "username", u.Username, "remote", r.RemoteAddr)
	_ = s.store.AuditEvent(r.Context(), u.Username, "sign_in", "session", u.ID,
		map[string]string{"ip": clientIP(r), "method": "hackspacelabs"})
	//nolint:gosec // G710: next was checked by hslsso.SafeNext when the sign-in started: a path on this site.
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// refuse logs and audits a HackSpaceLabs sign-in that was turned away.
func (s *srv) refuse(r *http.Request, username, why string) {
	s.log.Warn("HackSpaceLabs sign-in refused", "username", username, "reason", why, "remote", r.RemoteAddr)
	_ = s.store.AuditEvent(r.Context(), username, "sign_in_refused", "session", 0,
		map[string]string{"ip": clientIP(r), "method": "hackspacelabs", "reason": why})
}

func sessionLifetime(t hslsso.Tokens) time.Duration {
	if t.SessionLifetime > 0 {
		return t.SessionLifetime
	}
	return 96 * time.Hour
}

func (s *srv) sealTokens(subject string, t hslsso.Tokens) (string, error) {
	//nolint:gosec // G117: the tokens are marshaled only to be sealed with CPM_SECRET_KEY on the next line.
	raw, err := json.Marshal(sealedTokens{Subject: subject, RefreshToken: t.RefreshToken, IDToken: t.IDToken})
	if err != nil {
		return "", err
	}
	return s.box.Seal(string(raw), sealPurpose)
}

func (s *srv) openTokens(sealed string) (sealedTokens, error) {
	var t sealedTokens
	raw, err := s.box.Open(sealed, sealPurpose)
	if err != nil {
		return t, err
	}
	err = json.Unmarshal([]byte(raw), &t)
	return t, err
}

func (s *srv) hasSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	_, err = s.store.SessionUser(r.Context(), c.Value)
	return err == nil
}

// errSessionEnded means a HackSpaceLabs session was ended by its recheck.
var errSessionEnded = errors.New("session ended")

// recheck confirms a HackSpaceLabs session with Keycloak when it is due, and applies Keycloak's answer.
// It returns errSessionEnded when the session must end (already deleted here).
func (s *srv) recheck(ctx context.Context, token string, u store.User, ss store.Session) (store.User, error) {
	end := func(why string) (store.User, error) {
		s.log.Info("HackSpaceLabs session ended", "username", u.Username, "reason", why)
		_ = s.store.DeleteSession(ctx, token)
		_ = s.store.AuditEvent(ctx, u.Username, "session_ended", "session", u.ID,
			map[string]string{"method": "hackspacelabs", "reason": why})
		return u, errSessionEnded
	}
	if !s.ssoEnabled() {
		// Sign-in was turned off: nothing can recheck this session any more.
		return end("HackSpaceLabs sign-in is turned off")
	}
	every := s.sso.RecheckEvery
	if every <= 0 {
		every = time.Minute
	}
	if time.Since(ss.IDPCheckedAt) < every {
		return u, nil
	}
	// One recheck per session at a time; other requests carry on with what we have.
	key := hashOf(token)
	if _, busy := s.rechecks.LoadOrStore(key, struct{}{}); busy {
		return u, nil
	}
	defer s.rechecks.Delete(key)

	sealed, err := s.openTokens(ss.IDPTokens)
	if err != nil {
		return end("stored tokens unreadable")
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tokens, err := s.sso.Client.Refresh(rctx, sealed.RefreshToken, sealed.Subject)
	switch {
	case errors.Is(err, hslsso.ErrRefused), errors.Is(err, hslsso.ErrInvalidToken):
		return end(err.Error())
	case err != nil:
		s.log.Warn("couldn't recheck a HackSpaceLabs session; keeping it", "username", u.Username, "err", err)
		_ = s.store.MarkOIDCChecked(ctx, token)
		return u, nil
	}
	roles := hslsso.KnownRoles(tokens.Claims.Roles, ssoRoles...)
	if len(roles) == 0 {
		return end("no Switchyard role")
	}
	if roles[0] != u.Role {
		var conflict store.ConflictError
		if err := s.store.SyncOIDCRole(ctx, u.ID, roles[0]); errors.As(err, &conflict) {
			return end(string(conflict))
		} else if err != nil {
			return u, err
		}
		u.Role = roles[0]
	}
	resealed, err := s.sealTokens(sealed.Subject, tokens)
	if err != nil {
		return u, err
	}
	if err := s.store.RenewOIDCSession(ctx, token, sessionLifetime(tokens), resealed); err != nil {
		return u, err
	}
	return u, nil
}

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// endSessionRedirect is where the browser goes after signing out of a HackSpaceLabs session: Keycloak's
// sign-out (which ends the session in every app), or the signed-out page if Keycloak can't be reached.
func (s *srv) endSessionRedirect(ctx context.Context, ss store.Session) string {
	if !s.ssoEnabled() {
		return "/signed-out"
	}
	t, err := s.openTokens(ss.IDPTokens)
	if err != nil {
		return "/signed-out"
	}
	target, err := s.sso.Client.EndSessionURL(ctx, t.IDToken, s.sso.PublicURL+"/signed-out")
	if err != nil {
		s.log.Warn("couldn't build the HackSpaceLabs sign-out address", "err", err)
		return "/signed-out"
	}
	return target
}
