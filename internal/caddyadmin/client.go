// Package caddyadmin talks to Caddy's admin API. CPM only ever reaches it
// over a unix socket (spec §2, principle 5).
package caddyadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client calls the Caddy admin API over a unix socket.
type Client struct {
	socket string
	http   *http.Client
}

// New returns a client for the admin socket at path.
func New(socket string) *Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &Client{
		socket: socket,
		http: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

// Socket returns the socket path the client uses.
func (c *Client) Socket() string { return c.socket }

// Load replaces Caddy's whole config (POST /load). If Caddy rejects the
// config it keeps running the old one and the returned error carries
// Caddy's message.
func (c *Client) Load(ctx context.Context, config []byte) error {
	return c.load(ctx, config, false)
}

// Reload re-sends a config even if it's unchanged. Caddy then restarts its
// apps, which makes certificate management try again right away ("retry
// now" on the certificates page).
func (c *Client) Reload(ctx context.Context, config []byte) error {
	return c.load(ctx, config, true)
}

func (c *Client) load(ctx context.Context, config []byte, force bool) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/load", bytes.NewReader(config))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if force {
		req.Header.Set("Cache-Control", "must-revalidate")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("caddy admin: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return &LoadError{Status: resp.StatusCode, Message: e.Error}
		}
		return &LoadError{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	return nil
}

// LoadError is Caddy rejecting a config.
type LoadError struct {
	Status  int
	Message string
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("Caddy rejected the config (HTTP %d): %s", e.Status, e.Message)
}

// Config returns Caddy's running config as raw JSON (GET /config/).
func (c *Client) Config(ctx context.Context) ([]byte, error) {
	// Caddy checks the Host header on admin requests; "localhost" is accepted
	// for unix-socket listeners.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/config/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddy admin: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("caddy admin: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy admin: GET /config/: HTTP %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
