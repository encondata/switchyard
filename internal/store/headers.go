package store

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// HeaderRule changes one header. Values may use Caddy placeholders such as
// {http.request.remote.host}.
type HeaderRule struct {
	Op    string `json:"op"` // set | add | delete
	Name  string `json:"name"`
	Value string `json:"value"`
}

var headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")

// Headers that CPM manages itself or that would break proxying if changed.
var reservedHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "connection": true}

func normalizeHeaders(in []HeaderRule) []HeaderRule {
	out := []HeaderRule{}
	for _, h := range in {
		h.Op = strings.ToLower(strings.TrimSpace(h.Op))
		if h.Op == "" {
			h.Op = "set"
		}
		h.Name = strings.TrimSpace(h.Name)
		if h.Op == "delete" {
			h.Value = ""
		}
		if h.Name == "" && h.Value == "" {
			continue
		}
		out = append(out, h)
	}
	return out
}

func validateHeaders(rules []HeaderRule) string {
	if len(rules) > 50 {
		return "at most 50 header rules"
	}
	for _, h := range rules {
		switch h.Op {
		case "set", "add", "delete":
		default:
			return "each rule must set, add or delete"
		}
		if !headerNameRE.MatchString(h.Name) {
			return fmt.Sprintf("%q is not a valid header name", h.Name)
		}
		if reservedHeaders[strings.ToLower(h.Name)] {
			return fmt.Sprintf("%s is managed by Caddy and can't be changed here", h.Name)
		}
		if strings.ContainsAny(h.Value, "\r\n\x00") {
			return fmt.Sprintf("the value for %s can't contain line breaks", h.Name)
		}
		if msg := checkPlaceholders(h.Value); msg != "" {
			return fmt.Sprintf("%s: %s", h.Name, msg)
		}
		if len(h.Value) > 4096 {
			return fmt.Sprintf("the value for %s is too long", h.Name)
		}
		if h.Op != "delete" && h.Value == "" {
			return fmt.Sprintf("enter a value for %s (or choose delete)", h.Name)
		}
	}
	return ""
}

// checkPlaceholders allows only request/response placeholders ({http.…})
// in a header value. Others, such as {file.…} or {env.…}, could expose
// secrets (DNS tokens, environment) to visitors or upstreams.
func checkPlaceholders(v string) string {
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\\':
			i++ // escaped character, e.g. \{
		case '{':
			end := strings.IndexByte(v[i:], '}')
			if end < 0 {
				return "unclosed {"
			}
			name := v[i+1 : i+end]
			if !strings.HasPrefix(name, "http.") || strings.ContainsAny(name, "{\\") {
				return fmt.Sprintf("only {http.…} placeholders are allowed, not {%s}", name)
			}
			i += end
		}
	}
	return ""
}

func encodeHeaders(rules []HeaderRule) string {
	b, _ := json.Marshal(rules)
	return string(b)
}

func decodeHeaders(s string) []HeaderRule {
	var out []HeaderRule
	if json.Unmarshal([]byte(s), &out) != nil || out == nil {
		return []HeaderRule{}
	}
	return out
}

// Allowed top-level keys of a route in the advanced snippet.
var advancedRouteKeys = map[string]bool{"match": true, "handle": true, "terminal": true, "group": true}

// MaxAdvancedJSON caps the advanced snippet's size.
const MaxAdvancedJSON = 64 << 10

// ValidateAdvancedJSON checks the shape of a host's advanced snippet: a JSON
// array of Caddy route objects whose handlers name a "handler" module.
// Caddy itself checks the rest when the config is applied; if it refuses,
// it keeps running the previous config.
func ValidateAdvancedJSON(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if len(raw) > MaxAdvancedJSON {
		return "", fmt.Errorf("keep the snippet under %d KB", MaxAdvancedJSON>>10)
	}
	var routes []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &routes); err != nil {
		return "", fmt.Errorf("must be a JSON array of Caddy routes: %w", err)
	}
	for i, r := range routes {
		for k := range r {
			if !advancedRouteKeys[k] {
				return "", fmt.Errorf("route %d: unknown key %q (allowed: match, handle, terminal, group)", i+1, k)
			}
		}
		var handlers []map[string]json.RawMessage
		if h, ok := r["handle"]; ok {
			if err := json.Unmarshal(h, &handlers); err != nil {
				return "", fmt.Errorf("route %d: handle must be an array of handlers", i+1)
			}
		}
		for j, h := range handlers {
			var name string
			if json.Unmarshal(h["handler"], &name) != nil || name == "" {
				return "", fmt.Errorf("route %d, handler %d: missing \"handler\"", i+1, j+1)
			}
		}
	}
	// Re-encode compactly so the stored form is canonical.
	b, _ := json.Marshal(routes)
	return string(b), nil
}
