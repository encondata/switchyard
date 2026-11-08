package server

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"testing"
)

// withKey makes a request with an API key and no session.
func (c *client) withKey(header, token, method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if header == "Authorization" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set(header, token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestAPIKeyAccess(t *testing.T) {
	c := signedIn(t, &fakeCaddy{running: `{}`})

	// Only operations a key may have are accepted.
	for _, bad := range []string{`["apikeys.create"]`, `["auth.me"]`, `["nope.nope"]`, `["backup.restore"]`} {
		if code, body := c.do("POST", "/api/keys", `{"name":"x","permissions":`+bad+`}`); code != http.StatusBadRequest {
			t.Errorf("permissions %s = %d %v", bad, code, body)
		}
	}
	code, body := c.do("POST", "/api/keys", `{"name":"Deploy bot","permissions":["hosts.list","hosts.create"],"expires_at":"2099-12-31"}`)
	if code != http.StatusCreated {
		t.Fatalf("create key = %d %v", code, body)
	}
	token := body["token"].(string)
	id := strconv.Itoa(int(body["key"].(map[string]any)["id"].(float64)))

	// Allowed operations work without a session, with either header.
	if code, _ := c.withKey("Authorization", token, "GET", "/api/hosts", ""); code != 200 {
		t.Errorf("list hosts with key = %d", code)
	}
	code, body = c.withKey("X-API-Key", token, "POST", "/api/hosts", `{"type":"proxy","enabled":true,"domains":["bot.example.com"],"tls_mode":"auto","upstreams":[{"host":"app"}]}`)
	if code != http.StatusCreated {
		t.Fatalf("create host with key = %d %v", code, body)
	}
	hostID := strconv.Itoa(int(body["id"].(float64)))

	// Not given: refused with the permission it lacks.
	code, body = c.withKey("Authorization", token, "DELETE", "/api/hosts/"+hostID, "")
	if code != http.StatusForbidden || body["error"] != "missing_permission" || !strings.Contains(body["message"].(string), "hosts.delete") {
		t.Errorf("delete without permission = %d %v", code, body)
	}
	// Advanced JSON stays admin-only: hosts.create is an editor operation.
	code, _ = c.withKey("Authorization", token, "POST", "/api/hosts", `{"type":"proxy","enabled":true,"domains":["adv.example.com"],"tls_mode":"auto","upstreams":[{"host":"app"}],"advanced_json":"[{\"handle\":[]}]"}`)
	if code >= 200 && code < 300 {
		t.Errorf("key set advanced JSON: %d", code)
	}
	// Never for keys: account and key management.
	for _, p := range []string{"/api/keys", "/api/auth/me"} {
		if code, body := c.withKey("Authorization", token, "GET", p, ""); code != http.StatusForbidden || body["error"] != "not_for_api_keys" {
			t.Errorf("GET %s with key = %d %v", p, code, body)
		}
	}
	// Bad tokens.
	for _, bad := range []string{"sy_wrong", "", token + "x"} {
		if code, _ := c.withKey("Authorization", bad, "GET", "/api/hosts", ""); code != http.StatusUnauthorized {
			t.Errorf("token %q = %d", bad, code)
		}
	}

	// The audit log names the key.
	code, rows := c.doList("GET", "/api/audit?entity=host")
	if code != 200 || len(rows) == 0 || rows[0].(map[string]any)["username"] != "api:Deploy bot" {
		t.Errorf("audit = %d %v", code, rows)
	}

	// Add a permission without changing the token.
	if code, body := c.do("PUT", "/api/keys/"+id, `{"name":"Deploy bot","permissions":["hosts.list","hosts.create","hosts.delete"]}`); code != 200 {
		t.Fatalf("update key = %d %v", code, body)
	}
	if code, _ := c.withKey("Authorization", token, "DELETE", "/api/hosts/"+hostID, ""); code >= 300 {
		t.Errorf("delete after grant = %d", code)
	}
	code, keys := c.doList("GET", "/api/keys")
	if code != 200 || len(keys) != 1 || keys[0].(map[string]any)["last_used_at"] == nil {
		t.Errorf("keys = %d %v", code, keys)
	}
	if _, ok := keys[0].(map[string]any)["token"]; ok {
		t.Error("key list shows the token")
	}

	// Revoke: stops at once.
	if code, _ := c.do("POST", "/api/keys/"+id+"/revoke", ""); code != http.StatusNoContent {
		t.Fatalf("revoke = %d", code)
	}
	if code, _ := c.withKey("Authorization", token, "GET", "/api/hosts", ""); code != http.StatusUnauthorized {
		t.Errorf("revoked key = %d", code)
	}

	// The picker lists only operations keys can have.
	code, ops := c.doList("GET", "/api/keys/operations")
	if code != 200 || len(ops) < 40 {
		t.Fatalf("operations = %d (%d)", code, len(ops))
	}
	for _, o := range ops {
		if id := o.(map[string]any)["id"].(string); strings.HasPrefix(id, "auth.") || strings.HasPrefix(id, "apikeys.") || id == "backup.restore" {
			t.Errorf("operations offers %s", id)
		}
	}
}

func TestOnlyAdminsManageKeys(t *testing.T) {
	c := signedIn(t, &fakeCaddy{running: `{}`})
	if code, _ := c.do("POST", "/api/users", `{"username":"ed","role":"editor","password":"temp-pass-123"}`); code != http.StatusCreated {
		t.Fatalf("create editor = %d", code)
	}
	jar, _ := cookiejar.New(nil)
	ed := &client{t: t, base: c.base, http: &http.Client{Jar: jar}}
	ed.do("POST", "/api/auth/login", `{"username":"ed","password":"temp-pass-123"}`)
	ed.do("POST", "/api/auth/password", `{"current_password":"temp-pass-123","new_password":"another-pass-456"}`)
	if code, _ := ed.do("POST", "/api/keys", `{"name":"x","permissions":["hosts.list"]}`); code != http.StatusForbidden {
		t.Errorf("editor made a key: %d", code)
	}
	if code, _ := ed.doList("GET", "/api/keys"); code != http.StatusForbidden {
		t.Errorf("editor listed keys: %d", code)
	}
}

func TestOpenAPIDocument(t *testing.T) {
	c := signedIn(t, &fakeCaddy{running: `{}`})
	// Public: no session needed.
	resp, err := http.Get(c.base + "/api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || resp.StatusCode != 200 {
		t.Fatalf("openapi = %d %v", resp.StatusCode, err)
	}
	raw, _ := json.Marshal(doc)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	// Every $ref resolves.
	for _, m := range strings.Split(string(raw), `"$ref":"#/components/schemas/`)[1:] {
		name := m[:strings.Index(m, `"`)]
		if _, ok := schemas[name]; !ok {
			t.Errorf("unresolved $ref %s", name)
		}
	}
	// Every operation appears once, with a unique operationId.
	seen := map[string]bool{}
	count := 0
	for _, item := range doc["paths"].(map[string]any) {
		for _, op := range item.(map[string]any) {
			id := op.(map[string]any)["operationId"].(string)
			if seen[id] {
				t.Errorf("duplicate operationId %s", id)
			}
			seen[id] = true
			count++
		}
	}
	srv := &srv{}
	if want := len(srv.routes()); count != want {
		t.Errorf("document has %d operations, routes %d", count, want)
	}
	host := schemas["Host"].(map[string]any)["properties"].(map[string]any)
	for _, f := range []string{"domains", "upstreams", "tls_mode", "enabled"} {
		if _, ok := host[f]; !ok {
			t.Errorf("Host schema lacks %s", f)
		}
	}
}
