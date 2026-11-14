// Package cloudflare checks Cloudflare API tokens for the DNS challenge and
// manages DNS records (mail domains).
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// BaseURL is Cloudflare's API; tests point it at a local server.
var BaseURL = "https://api.cloudflare.com/client/v4"

var client = &http.Client{Timeout: 15 * time.Second}

// Result of checking a token.
type Result struct {
	Active bool     `json:"active"`
	Status string   `json:"status"`
	Zones  []string `json:"zones"`
	// Owner is "user" for tokens made under My Profile, "account" for
	// account-owned tokens.
	Owner string `json:"owner"`
	// ZonesError explains why zones couldn't be listed (usually a token
	// without Zone:Read, which caddy-dns/cloudflare needs).
	ZonesError string `json:"zones_error,omitempty"`
}

type cfError struct {
	Code       int       `json:"code"`
	Message    string    `json:"message"`
	ErrorChain []cfError `json:"error_chain"`
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []cfError       `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func get(ctx context.Context, token, path string) (envelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, BaseURL+path, nil)
	if err != nil {
		return envelope{}, err
	}
	return send(req, token)
}

func send(req *http.Request, token string) (envelope, error) {
	var env envelope
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return env, fmt.Errorf("can't reach Cloudflare: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &env); err != nil {
		return env, fmt.Errorf("unexpected reply from Cloudflare (HTTP %d)", resp.StatusCode)
	}
	if !env.Success {
		e := &APIError{Status: resp.StatusCode}
		if len(env.Errors) > 0 {
			first := env.Errors[0]
			e.Code, e.Message = first.Code, first.Message
			// The chain says what was actually wrong ("Invalid format for
			// Authorization header" under "Invalid request headers").
			for _, c := range first.ErrorChain {
				if c.Message != "" {
					e.Message += ": " + c.Message
				}
			}
		}
		return env, e
	}
	return env, nil
}

// APIError is an error answer from Cloudflare.
type APIError struct {
	Status  int    // HTTP status
	Code    int    // Cloudflare's error code (0 if none)
	Message string // Cloudflare's message
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", e.Status)
	}
	if e.Code != 0 {
		msg += fmt.Sprintf(" (code %d)", e.Code)
	}
	if h := e.Hint(); h != "" {
		msg += ". " + h
	}
	return "cloudflare: " + msg
}

// Codes Cloudflare answers with when it can't use the credentials at all.
var badTokenCodes = map[int]bool{1000: true, 9109: true}
var badHeaderCodes = map[int]bool{6003: true, 6100: true, 6101: true, 6102: true, 6103: true, 6111: true, 9103: true, 9106: true, 9107: true}

// BadToken reports whether Cloudflare rejected the token itself (as opposed
// to what it may do).
func (e *APIError) BadToken() bool {
	return badTokenCodes[e.Code] || badHeaderCodes[e.Code] || (e.Code == 0 && e.Status == http.StatusUnauthorized)
}

// Hint says what to do about the common errors.
func (e *APIError) Hint() string {
	switch {
	case badTokenCodes[e.Code] || (e.Code == 0 && e.Status == http.StatusUnauthorized):
		return "Cloudflare doesn't accept this token: it was deleted or rolled, or isn't an API token. " +
			"Create one under My Profile → API Tokens (not the Global API Key) and paste it again"
	case badHeaderCodes[e.Code]:
		return "Cloudflare couldn't read the token. Paste only the API token itself (not the Global API Key)"
	case e.Code == 10000 || e.Status == http.StatusForbidden:
		return "The token works but isn't allowed to do this: give it Zone → Zone → Read and Zone → DNS → Edit on this zone"
	}
	return ""
}

// Verify checks that a token is active and lists the zones it can see.
// Account-owned tokens (made under Manage Account → API Tokens) can't be
// checked at /user/tokens: Cloudflare calls them invalid there. They're
// checked at their account instead, found through the zones they can see.
func Verify(ctx context.Context, token string) (Result, error) {
	r := Result{Owner: "user", Zones: []string{}}
	env, err := get(ctx, token, "/user/tokens/verify")
	var zones []Zone
	var zerr error
	if err != nil {
		var ae *APIError
		if !errors.As(err, &ae) || !ae.BadToken() {
			return Result{}, err
		}
		zones, zerr = listZones(ctx, token)
		if zerr != nil || len(zones) == 0 || zones[0].Account.ID == "" {
			return Result{}, err // really not a token Cloudflare knows
		}
		aenv, aerr := get(ctx, token, "/accounts/"+url.PathEscape(zones[0].Account.ID)+"/tokens/verify")
		if aerr != nil {
			return Result{}, err
		}
		env, r.Owner = aenv, "account"
	} else {
		zones, zerr = listZones(ctx, token)
	}
	var v struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(env.Result, &v)
	r.Status, r.Active = v.Status, v.Status == "active"
	if zerr != nil {
		r.ZonesError = zerr.Error() + " (the token needs Zone → Zone → Read as well as Zone → DNS → Edit)"
		return r, nil
	}
	for _, z := range zones {
		r.Zones = append(r.Zones, z.Name)
	}
	sort.Strings(r.Zones)
	if len(r.Zones) == 0 {
		r.ZonesError = "the token can't see any zones; give it Zone → Zone → Read and Zone → DNS → Edit on your zones"
	}
	return r, nil
}

func listZones(ctx context.Context, token string) ([]Zone, error) {
	env, err := get(ctx, token, "/zones?per_page=50")
	if err != nil {
		return nil, err
	}
	var zones []Zone
	_ = json.Unmarshal(env.Result, &zones)
	return zones, nil
}
