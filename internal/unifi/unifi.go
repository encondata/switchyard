// Package unifi keeps Switchyard's ban list in a UniFi console's firewall,
// through the official UniFi Network Integration API (Network 10.x: an API
// key in X-API-Key, paths under /proxy/network/integration/v1). Bans become
// "traffic matching lists" (IPv4 and IPv6) that a firewall policy on the
// console blocks, so banned addresses are dropped at the gateway before they
// reach Caddy.
package unifi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one console.
type Client struct {
	BaseURL string // https://192.168.1.1
	APIKey  string
	// CertSHA256, if set, pins the console's certificate (consoles ship a
	// self-signed one): only a certificate with this SHA-256 is accepted.
	// Empty means normal certificate checks.
	CertSHA256 string
	HTTP       *http.Client // optional
}

// ErrCertChanged means the console presented a different certificate than
// the one pinned.
var ErrCertChanged = errors.New("the console's certificate isn't the one you trusted; if you replaced it, check the connection again and trust the new one")

// CertInfo describes a console's certificate, for the person to trust.
type CertInfo struct {
	SHA256  string    `json:"sha256"` // hex, lower case
	Subject string    `json:"subject"`
	Issuer  string    `json:"issuer"`
	Expires time.Time `json:"expires"`
	// Valid means it passes normal checks, so no pin is needed.
	Valid bool `json:"valid"`
}

// Fingerprint formats a hex SHA-256 the way browsers show it (AB:CD:...).
func Fingerprint(hexSum string) string {
	var parts []string
	for i := 0; i+2 <= len(hexSum); i += 2 {
		parts = append(parts, strings.ToUpper(hexSum[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// FetchCert reads the console's certificate with a bare TLS handshake (no
// request, so nothing, the API key included, is sent).
func FetchCert(ctx context.Context, baseURL string) (CertInfo, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return CertInfo{}, errors.New("use the console's https:// address")
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname()}} //nolint:gosec // only to read the certificate; nothing is sent
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return CertInfo{}, fmt.Errorf("can't reach the console at %s: %w", baseURL, err)
	}
	defer func() { _ = conn.Close() }()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertInfo{}, errors.New("the console sent no certificate")
	}
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: u.Hostname(), Intermediates: inter})
	return CertInfo{SHA256: hex.EncodeToString(sum[:]), Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(),
		Expires: leaf.NotAfter, Valid: verr == nil}, nil
}

// Site is one site on the console (a fabric can have several).
type Site struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	InternalReference string `json:"internalReference"`
}

// List is a traffic matching list.
type List struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name"`
	Type  string `json:"type"` // IPV4_ADDRESSES or IPV6_ADDRESSES
	Items []Item `json:"items,omitempty"`
}

// Item is one address (IP_ADDRESS) or network (SUBNET) in a list.
type Item struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Policy is the part of a firewall policy the sync reports on.
type Policy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Action  struct {
		Type string `json:"type"` // ALLOW, BLOCK or REJECT
	} `json:"action"`
	raw []byte
}

// Uses reports whether the policy refers to the list with this ID.
func (p Policy) Uses(listID string) bool {
	return listID != "" && bytes.Contains(p.raw, []byte(`"`+listID+`"`))
}

// APIError is an error answer from the console.
type APIError struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	switch {
	case e.Status == http.StatusUnauthorized:
		return "the console didn't accept the API key"
	case e.Status == http.StatusForbidden:
		return "the API key isn't allowed to do this (it acts as the admin who made it; use a Network admin)"
	case e.Message != "":
		return fmt.Sprintf("the console said: %s (%d)", e.Message, e.Status)
	}
	return fmt.Sprintf("the console answered %d", e.Status)
}

// IsNotFound reports whether err is a 404 from the console.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	if pin := strings.ToLower(c.CertSHA256); pin != "" {
		// Pinned: accept exactly that certificate (checked before any
		// request, so the key never goes to anything else).
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // replaced by the pin check below
			// VerifyConnection runs on every connection, resumed sessions
			// included (VerifyPeerCertificate is skipped on resumption).
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return ErrCertChanged
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if hex.EncodeToString(sum[:]) != pin {
					return ErrCertChanged
				}
				return nil
			},
		}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: t,
		// The API doesn't redirect; a redirect means the wrong address (or
		// the sign-in page), which shouldn't be followed with the key.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+"/proxy/network/integration"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client().Do(req)
	if err != nil {
		if errors.Is(err, ErrCertChanged) {
			return ErrCertChanged
		}
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) {
			return errors.New("the console's certificate isn't trusted; use Check connection to trust it")
		}
		return fmt.Errorf("can't reach the console at %s: %w", c.BaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("the console redirected to %s; check the address (it should be the console itself, e.g. https://192.168.1.1)", resp.Header.Get("Location"))
	}
	if resp.StatusCode >= 400 {
		e := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(b, e)
		return e
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return errors.New("that address answered, but not like the UniFi Network API; check it's the console and that Network is 10.x or newer")
	}
	return nil
}

type page[T any] struct {
	Data       []T   `json:"data"`
	Count      int   `json:"count"`
	TotalCount int64 `json:"totalCount"`
}

// all reads every page of a list endpoint.
func all[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var out []T
	for offset := 0; ; {
		var p page[json.RawMessage]
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf("%s%soffset=%d&limit=200", path, sep, offset), nil, &p); err != nil {
			return nil, err
		}
		for _, raw := range p.Data {
			var v T
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, err
			}
			if pol, ok := any(&v).(*Policy); ok {
				pol.raw = raw
			}
			out = append(out, v)
		}
		offset += len(p.Data)
		if len(p.Data) == 0 || int64(offset) >= p.TotalCount {
			return out, nil
		}
	}
}

// Sites lists the console's sites.
func (c *Client) Sites(ctx context.Context) ([]Site, error) {
	return all[Site](ctx, c, "/v1/sites")
}

// Lists lists a site's traffic matching lists (without their items).
func (c *Client) Lists(ctx context.Context, siteID string) ([]List, error) {
	return all[List](ctx, c, "/v1/sites/"+url.PathEscape(siteID)+"/traffic-matching-lists")
}

// CreateList makes a list and returns it with its ID.
func (c *Client) CreateList(ctx context.Context, siteID string, l List) (List, error) {
	var out List
	l.ID = ""
	err := c.do(ctx, http.MethodPost, "/v1/sites/"+url.PathEscape(siteID)+"/traffic-matching-lists", l, &out)
	return out, err
}

// UpdateList replaces a list's name and items.
func (c *Client) UpdateList(ctx context.Context, siteID, listID string, l List) error {
	l.ID = ""
	return c.do(ctx, http.MethodPut, "/v1/sites/"+url.PathEscape(siteID)+"/traffic-matching-lists/"+url.PathEscape(listID), l, nil)
}

// Policies lists a site's firewall policies.
func (c *Client) Policies(ctx context.Context, siteID string) ([]Policy, error) {
	return all[Policy](ctx, c, "/v1/sites/"+url.PathEscape(siteID)+"/firewall/policies")
}
