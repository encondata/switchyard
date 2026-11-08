package npmimport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIConfig is how to reach a running NPM and sign in to its API. The
// password is used once to get a token and isn't stored.
type APIConfig struct {
	// URL is NPM's admin address, e.g. http://192.168.1.10:81.
	URL      string `json:"url"`
	Email    string `json:"email"`
	Password string `json:"password"`
	// InsecureTLS skips certificate checks for an https URL with a
	// self-signed certificate.
	InsecureTLS bool `json:"insecure_tls"`
}

// apiTables maps NPM tables to the API endpoints that list them.
var apiTables = map[string]string{
	"proxy_host":       "/api/nginx/proxy-hosts",
	"redirection_host": "/api/nginx/redirection-hosts",
	"dead_host":        "/api/nginx/dead-hosts",
	"stream":           "/api/nginx/streams",
	"certificate":      "/api/nginx/certificates",
}

const maxAPIBody = 32 << 20

// FetchAPI signs in to NPM's API and reads everything the import needs.
func FetchAPI(ctx context.Context, c APIConfig) (Source, error) {
	base, err := normalizeURL(c.URL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.Email) == "" || c.Password == "" {
		return nil, errors.New("enter the email and password of an NPM admin")
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		// A redirect usually means the wrong address; say so instead of following it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if c.InsecureTLS {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // opt-in for self-signed NPM
	}
	a := &apiSource{client: client, base: base, tables: map[string][]row{}}
	if err := a.login(ctx, strings.TrimSpace(c.Email), c.Password); err != nil {
		return nil, err
	}
	for table, path := range apiTables {
		rows, err := a.list(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("reading %s from NPM: %w", path, err)
		}
		a.tables[table] = rows
	}
	// Access lists come with their entries; split them into the two tables
	// the database has, so the conversion is the same either way.
	lists, err := a.list(ctx, "/api/nginx/access-lists?expand=items,clients")
	if err != nil {
		return nil, fmt.Errorf("reading access lists from NPM: %w", err)
	}
	var auths, clients []row
	for _, l := range lists {
		id := l["id"]
		for _, k := range []string{"items", "clients"} {
			entries, _ := l[k].([]any)
			for _, e := range entries {
				m, ok := e.(map[string]any)
				if !ok {
					continue
				}
				r := row(m)
				r["access_list_id"] = id
				if k == "items" {
					auths = append(auths, r)
				} else {
					clients = append(clients, r)
				}
			}
		}
		delete(l, "items")
		delete(l, "clients")
	}
	a.tables["access_list"] = lists
	a.tables["access_list_auth"] = auths
	a.tables["access_list_client"] = clients
	return a, nil
}

func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" && !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("enter NPM's address, like http://192.168.1.10:81")
	}
	p := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/api")
	return u.Scheme + "://" + u.Host + strings.TrimSuffix(p, "/"), nil
}

type apiSource struct {
	client *http.Client
	base   string
	token  string
	tables map[string][]row
}

func (a *apiSource) Ping(context.Context) error { return nil }

func (a *apiSource) Table(_ context.Context, name string) ([]row, error) {
	rows, ok := a.tables[name]
	if !ok {
		return nil, fmt.Errorf("NPM's API has no %s list", name)
	}
	return rows, nil
}

func (a *apiSource) login(ctx context.Context, email, password string) error {
	body, _ := json.Marshal(map[string]string{"identity": email, "secret": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/api/tokens", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		Token       string `json:"token"`
		Requires2FA bool   `json:"requires_2fa"`
	}
	status, err := a.do(req, &out)
	switch {
	case err != nil && status == 0:
		return err
	case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusBadRequest:
		return errors.New("NPM didn't accept that email and password")
	case err != nil:
		return err
	case out.Requires2FA:
		return errors.New("this NPM account uses two-factor sign-in, which the import can't do; use an admin account without it")
	case out.Token == "":
		return errors.New("NPM answered without a sign-in token; check the address points at NPM's admin port (usually 81)")
	}
	a.token = out.Token
	return nil
}

func (a *apiSource) list(ctx context.Context, path string) ([]row, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	var items []map[string]any
	if status, err := a.do(req, &items); err != nil {
		if status == http.StatusForbidden || status == http.StatusUnauthorized {
			return nil, errors.New("this NPM user can't list everything; sign in as an NPM admin")
		}
		return nil, err
	}
	out := make([]row, 0, len(items))
	for _, it := range items {
		r := row(it)
		if r.bool("is_deleted") {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// do sends req and decodes a JSON answer into v. It returns the HTTP status
// (0 if NPM couldn't be reached).
func (a *apiSource) do(req *http.Request, v any) (int, error) {
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("can't reach NPM at %s: %w", a.base, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, fmt.Errorf("NPM redirected to %s; use that address instead", resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error.Message != "" {
			return resp.StatusCode, fmt.Errorf("NPM said: %s", e.Error.Message)
		}
		return resp.StatusCode, fmt.Errorf("NPM answered %s", resp.Status)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return resp.StatusCode, errors.New("that address answered, but not like NPM's API; check it points at NPM's admin port (usually 81)")
	}
	return resp.StatusCode, nil
}
