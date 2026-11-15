package purelymail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Purelymail's API (spec: https://news.purelymail.com/api/index.html).
// Every call is a POST of JSON to /api/v0/<operation>, authenticated with
// the account's API token in the Purelymail-Api-Token header.

// APIBaseURL is Purelymail's API; tests point it at a local server.
var APIBaseURL = "https://purelymail.com/api/v0"

var apiClient = &http.Client{Timeout: 20 * time.Second}

// Client calls Purelymail's API with one account's token.
type Client struct{ Token string }

// DNSSummary is Purelymail's own view of a domain's records.
type DNSSummary struct {
	PassesMx    bool `json:"passesMx"`
	PassesSpf   bool `json:"passesSpf"`
	PassesDkim  bool `json:"passesDkim"`
	PassesDmarc bool `json:"passesDmarc"`
}

// AllPass reports whether Purelymail is happy with every record.
func (d DNSSummary) AllPass() bool { return d.PassesMx && d.PassesSpf && d.PassesDkim && d.PassesDmarc }

// DomainInfo is a domain on the Purelymail account.
type DomainInfo struct {
	Name       string     `json:"name"`
	IsShared   bool       `json:"isShared"`
	DNSSummary DNSSummary `json:"dnsSummary"`
}

// APIError is an error answer from Purelymail.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", e.Status)
	}
	if e.Code != "" {
		msg += " (" + e.Code + ")"
	}
	return "purelymail: " + msg
}

// BadKey reports whether Purelymail turned the API token down.
func (e *APIError) BadKey() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

func (c Client) call(ctx context.Context, op string, body, out any) error {
	if body == nil {
		body = struct{}{}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, APIBaseURL+"/"+op, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Purelymail-Api-Token", c.Token)
	resp, err := apiClient.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach Purelymail: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env struct {
		Type    string          `json:"type"`
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Result  json.RawMessage `json:"result"`
	}
	jerr := json.Unmarshal(raw, &env)
	if resp.StatusCode != http.StatusOK || env.Type == "error" || (jerr == nil && env.Result == nil && env.Message != "") {
		e := &APIError{Status: resp.StatusCode, Code: env.Code, Message: env.Message}
		if e.Message == "" && jerr != nil {
			e.Message = strings.TrimSpace(string(raw[:min(len(raw), 200)]))
		}
		return e
	}
	if jerr != nil {
		return fmt.Errorf("unexpected reply from Purelymail (HTTP %d)", resp.StatusCode)
	}
	if out != nil && env.Result != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("unexpected reply from Purelymail: %w", err)
		}
	}
	return nil
}

// OwnershipCode returns the value of the account's ownership proof TXT
// record (the same for every domain).
func (c Client) OwnershipCode(ctx context.Context) (string, error) {
	var r struct {
		Code string `json:"code"`
	}
	if err := c.call(ctx, "getOwnershipCode", nil, &r); err != nil {
		return "", err
	}
	if r.Code == "" {
		return "", errors.New("purelymail: no ownership code in the reply")
	}
	return r.Code, nil
}

// ListDomains returns the account's own domains (not Purelymail's shared
// ones).
func (c Client) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	var r struct {
		Domains []DomainInfo `json:"domains"`
	}
	if err := c.call(ctx, "listDomains", map[string]bool{"includeShared": false}, &r); err != nil {
		return nil, err
	}
	return r.Domains, nil
}

// FindDomain returns the account's entry for name, if it has one.
func (c Client) FindDomain(ctx context.Context, name string) (*DomainInfo, error) {
	ds, err := c.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range ds {
		if strings.EqualFold(d.Name, name) {
			return &d, nil
		}
	}
	return nil, nil
}

// AddDomain adds a domain to the account. Purelymail checks its DNS
// (ownership proof and records) first and refuses if they aren't there.
func (c Client) AddDomain(ctx context.Context, name string) error {
	return c.call(ctx, "addDomain", map[string]string{"domainName": name}, nil)
}

// RecheckDNS asks Purelymail to look at a domain's records again.
func (c Client) RecheckDNS(ctx context.Context, name string) error {
	return c.call(ctx, "updateDomainSettings", map[string]any{"name": name, "recheckDns": true}, nil)
}

// ListUsers returns every user (full address) on the account.
func (c Client) ListUsers(ctx context.Context) ([]string, error) {
	var r struct {
		Users []string `json:"users"`
	}
	if err := c.call(ctx, "listUser", nil, &r); err != nil {
		return nil, err
	}
	return r.Users, nil
}

// CreateUser makes a mailbox, local@domain. Switchyard keeps the password,
// so Purelymail's password reset (which needs a recovery address) and its
// welcome email are off.
func (c Client) CreateUser(ctx context.Context, local, domain, password string) error {
	return c.call(ctx, "createUser", map[string]any{
		"userName":            local,
		"domainName":          domain,
		"password":            password,
		"enablePasswordReset": false,
		"sendWelcomeEmail":    false,
	}, nil)
}

// SetPassword changes a user's password.
func (c Client) SetPassword(ctx context.Context, address, password string) error {
	return c.call(ctx, "modifyUser", map[string]string{"userName": address, "newPassword": password}, nil)
}

// DeleteUser deletes a user and its mail.
func (c Client) DeleteUser(ctx context.Context, address string) error {
	return c.call(ctx, "deleteUser", map[string]string{"userName": address}, nil)
}
