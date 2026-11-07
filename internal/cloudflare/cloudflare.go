// Package cloudflare checks Cloudflare API tokens for the DNS challenge.
package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	// ZonesError explains why zones couldn't be listed (usually a token
	// without Zone:Read, which caddy-dns/cloudflare needs).
	ZonesError string `json:"zones_error,omitempty"`
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func get(ctx context.Context, token, path string) (envelope, error) {
	var env envelope
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, BaseURL+path, nil)
	if err != nil {
		return env, err
	}
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
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if len(env.Errors) > 0 {
			msg = env.Errors[0].Message
		}
		return env, fmt.Errorf("cloudflare: %s", msg)
	}
	return env, nil
}

// Verify checks that a token is active and lists the zones it can see.
func Verify(ctx context.Context, token string) (Result, error) {
	env, err := get(ctx, token, "/user/tokens/verify")
	if err != nil {
		return Result{}, err
	}
	var v struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(env.Result, &v)
	r := Result{Status: v.Status, Active: v.Status == "active", Zones: []string{}}
	zenv, err := get(ctx, token, "/zones?per_page=50")
	if err != nil {
		r.ZonesError = err.Error() + " (the token needs Zone → Zone → Read as well as Zone → DNS → Edit)"
		return r, nil
	}
	var zones []struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(zenv.Result, &zones)
	for _, z := range zones {
		r.Zones = append(r.Zones, z.Name)
	}
	sort.Strings(r.Zones)
	if len(r.Zones) == 0 {
		r.ZonesError = "the token can't see any zones; give it Zone → Zone → Read and Zone → DNS → Edit on your zones"
	}
	return r, nil
}
