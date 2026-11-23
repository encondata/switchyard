// Package hslsso signs people in with the HackSpaceLabs Keycloak (OpenID Connect, authorization code
// with PKCE S256, state and nonce) and rechecks their session with refresh tokens.
//
// It follows the contract in PLAN.md section 5 of encondata/hsl-suite and has no dependencies on the
// rest of Switchyard, so other HackSpaceLabs apps can take a copy of this folder.
//
// Discovery is lazy: nothing is fetched until the first sign-in or recheck, a failure is retried on the
// next call, and a working configuration is kept for an hour. An app must never fail to start, or turn
// sign-in off, because Keycloak was not reachable when it started.
package hslsso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config describes one app's Keycloak client.
type Config struct {
	// Issuer is the realm's full issuer, e.g. https://auth.hackspacelabs.com/realms/hackspacelabs.
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is the app's callback: its public URL plus the callback path.
	RedirectURL string
	// InternalURL, if set, is an origin (scheme://host[:port]) used for server-to-server calls
	// (discovery, token, keys) when the app can't reach the public issuer address. Browser redirects
	// and the issuer check always use Issuer.
	InternalURL string
	// HTTPClient is used for calls to Keycloak. Default: 10-second timeout.
	HTTPClient *http.Client
	// Now is for tests. Default: time.Now.
	Now func() time.Time
}

// Claims are the ID-token claims the apps use.
type Claims struct {
	Subject           string   `json:"sub"`
	SessionID         string   `json:"sid"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Roles             []string `json:"hsl_roles"`
	Nonce             string   `json:"nonce"`
	AuthTime          int64    `json:"auth_time"`
	AuthorizedParty   string   `json:"azp"`
}

// Tokens is the result of a sign-in or a recheck.
type Tokens struct {
	Claims       Claims
	IDToken      string
	RefreshToken string
	// SessionLifetime is Keycloak's refresh_expires_in: how much longer its session lasts (96 hours, or
	// 30 days with "Remember me"). Zero when Keycloak did not say.
	SessionLifetime time.Duration
}

var (
	// ErrRefused means Keycloak definitely ended the session (invalid_grant: signed out, disabled,
	// expired) or answered for a different person. End the app's session.
	ErrRefused = errors.New("hslsso: Keycloak refused the session")
	// ErrInvalidToken means an ID token failed verification. End the session or refuse the sign-in.
	ErrInvalidToken = errors.New("hslsso: invalid ID token")
	// ErrUnavailable wraps everything else (network, timeouts, 5xx, discovery): keep the app's session
	// and try again later.
	ErrUnavailable = errors.New("hslsso: Keycloak unavailable")
)

// Client talks to Keycloak for one app. It is safe for concurrent use.
type Client struct {
	cfg Config

	mu      sync.Mutex
	current *provider
}

type provider struct {
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	endSession string
	fetched    time.Time
}

// New checks the configuration. It does not contact Keycloak.
func New(cfg Config) (*Client, error) {
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if err := checkURL(cfg.Issuer, true); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("client id and secret are required")
	}
	if err := checkURL(cfg.RedirectURL, true); err != nil {
		return nil, fmt.Errorf("redirect URL: %w", err)
	}
	if cfg.InternalURL != "" {
		cfg.InternalURL = strings.TrimRight(cfg.InternalURL, "/")
		if err := checkURL(cfg.InternalURL, false); err != nil {
			return nil, fmt.Errorf("internal URL: %w", err)
		}
		if u, _ := url.Parse(cfg.InternalURL); u.Path != "" {
			return nil, errors.New("internal URL must be an origin, without a path")
		}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{cfg: cfg}, nil
}

func checkURL(raw string, pathAllowed bool) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("must be an http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (!pathAllowed && u.Path != "" && u.Path != "/") {
		return errors.New("must not contain credentials, a query or a fragment")
	}
	return nil
}

// ClientID is the app's Keycloak client id.
func (c *Client) ClientID() string { return c.cfg.ClientID }

type discoveryDoc struct {
	Issuer             string   `json:"issuer"`
	AuthURL            string   `json:"authorization_endpoint"`
	TokenURL           string   `json:"token_endpoint"`
	JWKSURL            string   `json:"jwks_uri"`
	UserInfoURL        string   `json:"userinfo_endpoint"`
	EndSessionURL      string   `json:"end_session_endpoint"`
	CodeChallengeTypes []string `json:"code_challenge_methods_supported"`
}

// provider returns the discovered configuration, fetching it when there is none or it is over an hour
// old. If a refetch fails, the last good one is kept.
func (c *Client) provider(ctx context.Context) (*provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil && c.cfg.Now().Sub(c.current.fetched) < time.Hour {
		return c.current, nil
	}
	p, err := c.discover(ctx)
	if err != nil {
		if c.current != nil {
			return c.current, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c.current = p
	return p, nil
}

func (c *Client) discover(ctx context.Context) (*provider, error) {
	base := c.cfg.Issuer
	if c.cfg.InternalURL != "" {
		base = withOrigin(c.cfg.Issuer, c.cfg.InternalURL)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: HTTP %d", resp.StatusCode)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	if doc.Issuer != c.cfg.Issuer {
		return nil, fmt.Errorf("discovery: issuer is %q, expected %q", doc.Issuer, c.cfg.Issuer)
	}
	if doc.AuthURL == "" || doc.TokenURL == "" || doc.JWKSURL == "" {
		return nil, errors.New("discovery: missing endpoints")
	}
	if len(doc.CodeChallengeTypes) > 0 && !slices.Contains(doc.CodeChallengeTypes, "S256") {
		return nil, errors.New("discovery: PKCE S256 not supported")
	}
	if c.cfg.InternalURL != "" {
		doc.TokenURL = withOrigin(doc.TokenURL, c.cfg.InternalURL)
		doc.JWKSURL = withOrigin(doc.JWKSURL, c.cfg.InternalURL)
		if doc.UserInfoURL != "" {
			doc.UserInfoURL = withOrigin(doc.UserInfoURL, c.cfg.InternalURL)
		}
	}
	// The key set keeps this context for later key fetches, so it must not be the request's.
	keyCtx := oidc.ClientContext(context.Background(), c.cfg.HTTPClient)
	op := (&oidc.ProviderConfig{
		IssuerURL:   doc.Issuer,
		AuthURL:     doc.AuthURL,
		TokenURL:    doc.TokenURL,
		UserInfoURL: doc.UserInfoURL,
		JWKSURL:     doc.JWKSURL,
		Algorithms:  []string{oidc.RS256},
	}).NewProvider(keyCtx)
	return &provider{
		oauth: oauth2.Config{
			ClientID:     c.cfg.ClientID,
			ClientSecret: c.cfg.ClientSecret,
			Endpoint:     oauth2.Endpoint{AuthURL: doc.AuthURL, TokenURL: doc.TokenURL, AuthStyle: oauth2.AuthStyleInHeader},
			RedirectURL:  c.cfg.RedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: op.Verifier(&oidc.Config{
			ClientID:             c.cfg.ClientID,
			SupportedSigningAlgs: []string{oidc.RS256},
			Now:                  c.cfg.Now,
		}),
		endSession: doc.EndSessionURL,
		fetched:    c.cfg.Now(),
	}, nil
}

// withOrigin replaces raw's scheme and host with those of origin.
func withOrigin(raw, origin string) string {
	u, err := url.Parse(raw)
	o, err2 := url.Parse(origin)
	if err != nil || err2 != nil {
		return raw
	}
	u.Scheme, u.Host = o.Scheme, o.Host
	return u.String()
}

// Flow is one sign-in attempt's secrets. Keep all three server-side (or in a signed cookie) until the
// callback, and bind the attempt to the browser with a cookie (PLAN.md 5.4).
type Flow struct {
	State, Nonce, Verifier string
}

// NewFlow makes a flow's random values.
func NewFlow() (Flow, error) {
	var f Flow
	for _, p := range []*string{&f.State, &f.Nonce} {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return f, err
		}
		*p = base64.RawURLEncoding.EncodeToString(b)
	}
	f.Verifier = oauth2.GenerateVerifier()
	return f, nil
}

// AuthURL is where to send the browser to sign in. prompt may be "" or "login" (ask for the password
// even when Keycloak has a session).
func (c *Client) AuthURL(ctx context.Context, f Flow, prompt string) (string, error) {
	p, err := c.provider(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(f.Verifier), oidc.Nonce(f.Nonce)}
	if prompt == "login" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	}
	return p.oauth.AuthCodeURL(f.State, opts...), nil
}

// Exchange turns the callback's code into tokens and verifies the ID token, including its nonce.
func (c *Client) Exchange(ctx context.Context, code string, f Flow) (Tokens, error) {
	p, err := c.provider(ctx)
	if err != nil {
		return Tokens{}, err
	}
	ctx = oidc.ClientContext(ctx, c.cfg.HTTPClient)
	tok, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(f.Verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil && re.Response.StatusCode < 500 {
			return Tokens{}, fmt.Errorf("%w: code exchange: %s", ErrRefused, re.ErrorCode)
		}
		return Tokens{}, fmt.Errorf("%w: code exchange: %v", ErrUnavailable, err)
	}
	return c.tokens(ctx, p, tok, "", f.Nonce)
}

// Refresh rechecks a session. ErrRefused or ErrInvalidToken: end it. ErrUnavailable: keep it and try
// again later. subject is the person the session belongs to; an answer for anyone else is refused.
func (c *Client) Refresh(ctx context.Context, refreshToken, subject string) (Tokens, error) {
	p, err := c.provider(ctx)
	if err != nil {
		return Tokens{}, err
	}
	ctx = oidc.ClientContext(ctx, c.cfg.HTTPClient)
	tok, err := p.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.ErrorCode == "invalid_grant" {
			return Tokens{}, fmt.Errorf("%w: %s", ErrRefused, re.ErrorDescription)
		}
		return Tokens{}, fmt.Errorf("%w: refresh: %v", ErrUnavailable, err)
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return c.tokens(ctx, p, tok, subject, "")
}

func (c *Client) tokens(ctx context.Context, p *provider, tok *oauth2.Token, subject, nonce string) (Tokens, error) {
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Tokens{}, fmt.Errorf("%w: no ID token in the response", ErrInvalidToken)
	}
	claims, err := c.verify(ctx, p, raw, nonce)
	if err != nil {
		return Tokens{}, err
	}
	if subject != "" && claims.Subject != subject {
		return Tokens{}, fmt.Errorf("%w: the session now belongs to someone else", ErrRefused)
	}
	out := Tokens{Claims: claims, IDToken: raw, RefreshToken: tok.RefreshToken}
	if n, ok := tok.Extra("refresh_expires_in").(float64); ok && n > 0 {
		out.SessionLifetime = time.Duration(n) * time.Second
	}
	return out, nil
}

func (c *Client) verify(ctx context.Context, p *provider, raw, nonce string) (Claims, error) {
	idt, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	var cl Claims
	if err := idt.Claims(&cl); err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if cl.Subject == "" {
		return Claims{}, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	if len(idt.Audience) > 1 && cl.AuthorizedParty != c.cfg.ClientID {
		return Claims{}, fmt.Errorf("%w: issued to another client", ErrInvalidToken)
	}
	if nonce != "" && cl.Nonce != nonce {
		return Claims{}, fmt.Errorf("%w: nonce does not match", ErrInvalidToken)
	}
	return cl, nil
}

// EndSessionURL is Keycloak's sign-out address for this session, returning to postLogout afterwards.
// postLogout must be registered on the client exactly (PLAN.md uses <public url>/signed-out).
func (c *Client) EndSessionURL(ctx context.Context, idToken, postLogout string) (string, error) {
	p, err := c.provider(ctx)
	if err != nil {
		return "", err
	}
	if p.endSession == "" {
		return "", fmt.Errorf("%w: no end_session_endpoint", ErrUnavailable)
	}
	q := url.Values{"client_id": {c.cfg.ClientID}, "post_logout_redirect_uri": {postLogout}}
	if idToken != "" {
		q.Set("id_token_hint", idToken)
	}
	return p.endSession + "?" + q.Encode(), nil
}

// KnownRoles keeps the roles from the claim that the app knows, in the app's order.
func KnownRoles(claimed []string, known ...string) []string {
	var out []string
	for _, k := range known {
		if slices.Contains(claimed, k) {
			out = append(out, k)
		}
	}
	return out
}

// SafeNext returns next if it is a path on this site, otherwise "/". It allows a query and a fragment
// (single-page apps put their route there, e.g. "/#/hosts/3").
func SafeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\") {
		return "/"
	}
	for _, r := range next {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	if len(next) > 2000 {
		return "/"
	}
	return next
}
