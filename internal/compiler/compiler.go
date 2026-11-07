// Package compiler turns CPM's database state into one complete Caddy JSON
// config (spec §2). The output is deterministic: the same hosts always give
// byte-identical JSON, so hashes can be compared for pending changes and
// drift.
//
// Layout of the generated config:
//
//   - admin: the unix socket CPM talks to (never a TCP port)
//   - server "cpm_http" on :80: hosts with TLS off, HTTP→HTTPS redirects for
//     TLS hosts with force HTTPS, the TLS hosts themselves when force HTTPS
//     is off, then a catch-all 404
//   - server "cpm_https" on :443: every TLS host, then a catch-all 404.
//     Caddy's automatic redirects are disabled because CPM writes them.
//   - tls automation: an internal-CA policy for hosts with TLS "internal";
//     everything else uses Caddy's default ACME issuers. On-demand TLS is
//     never enabled.
package compiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/encondata/caddyproxymanager/internal/store"
)

// Settings are the parts of the config that don't come from hosts.
type Settings struct {
	// AdminListen is Caddy's admin listener, e.g. "unix//run/caddy/admin.sock|0660".
	AdminListen string
}

// Server and route IDs that other code (and tests) can rely on.
const (
	HTTPServer  = "cpm_http"
	HTTPSServer = "cpm_https"
)

const notConfiguredBody = "No site is configured for this address.\n"

type obj = map[string]any

// Compile builds the full Caddy config for the given hosts. Disabled hosts
// are left out.
func Compile(s Settings, hosts []store.Host) ([]byte, error) {
	if s.AdminListen == "" {
		return nil, fmt.Errorf("compiler: admin listen address is required")
	}
	enabled := make([]store.Host, 0, len(hosts))
	for _, h := range hosts {
		if h.Enabled {
			enabled = append(enabled, h)
		}
	}
	sort.Slice(enabled, func(i, j int) bool { return enabled[i].ID < enabled[j].ID })

	var httpRoutes, httpsRoutes []any
	var internalSubjects []string
	for _, h := range enabled {
		route, err := hostRoute(h)
		if err != nil {
			return nil, fmt.Errorf("compiler: host %d: %w", h.ID, err)
		}
		if h.TLSMode == store.TLSOff {
			httpRoutes = append(httpRoutes, route)
			continue
		}
		httpsRoutes = append(httpsRoutes, route)
		if h.ForceHTTPS {
			httpRoutes = append(httpRoutes, redirectToHTTPSRoute(h))
		} else {
			plain, _ := hostRoute(h) // same handlers, also on :80
			plain["@id"] = fmt.Sprintf("cpm_host_%d_http", h.ID)
			httpRoutes = append(httpRoutes, plain)
		}
		if h.TLSMode == store.TLSInternal {
			internalSubjects = append(internalSubjects, h.Domains...)
		}
	}
	httpRoutes = append(httpRoutes, notConfiguredRoute("http"))
	httpsRoutes = append(httpsRoutes, notConfiguredRoute("https"))

	cfg := obj{
		"admin": obj{
			"listen": s.AdminListen,
			"config": obj{"persist": false},
		},
		"apps": obj{
			"http": obj{
				"servers": obj{
					HTTPServer: obj{
						"listen": []string{":80"},
						"routes": httpRoutes,
					},
					HTTPSServer: obj{
						"listen":          []string{":443"},
						"routes":          httpsRoutes,
						"automatic_https": obj{"disable_redirects": true},
					},
				},
			},
			// The internal CA's root can't be installed into a container's
			// trust store; don't try.
			"pki": obj{"certificate_authorities": obj{"local": obj{"install_trust": false}}},
		},
	}
	if len(internalSubjects) > 0 {
		cfg["apps"].(obj)["tls"] = obj{
			"automation": obj{
				"policies": []any{
					obj{
						"subjects": internalSubjects,
						"issuers":  []any{obj{"module": "internal"}},
					},
				},
			},
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func hostRoute(h store.Host) (obj, error) {
	var handlers []any
	if h.HSTS && h.TLSMode != store.TLSOff {
		handlers = append(handlers, obj{
			"handler":  "headers",
			"response": obj{"set": obj{"Strict-Transport-Security": []string{"max-age=31536000"}}},
		})
	}
	switch h.Type {
	case store.HostProxy:
		if h.Compression {
			handlers = append(handlers, obj{
				"handler":   "encode",
				"encodings": obj{"zstd": obj{}, "gzip": obj{}},
				"prefer":    []string{"zstd", "gzip"},
			})
		}
		handlers = append(handlers, proxyHandler(h))
	case store.HostRedirect:
		loc := h.RedirectTo
		if h.PreservePath {
			loc = trimSlash(loc) + "{http.request.uri}"
		}
		handlers = append(handlers, obj{
			"handler":     "static_response",
			"status_code": strconv.Itoa(h.RedirectCode),
			"headers":     obj{"Location": []string{loc}},
		})
	case store.Host404:
		handlers = append(handlers, obj{
			"handler":     "static_response",
			"status_code": "404",
			"headers":     obj{"Content-Type": []string{"text/plain; charset=utf-8"}},
			"body":        "Not found.\n",
		})
	default:
		return nil, fmt.Errorf("unknown host type %q", h.Type)
	}
	return obj{
		"@id":      fmt.Sprintf("cpm_host_%d", h.ID),
		"match":    []any{obj{"host": h.Domains}},
		"handle":   []any{obj{"handler": "subroute", "routes": []any{obj{"handle": handlers}}}},
		"terminal": true,
	}, nil
}

func proxyHandler(h store.Host) obj {
	upstreams := make([]any, 0, len(h.Upstreams))
	useTLS, skipVerify := false, false
	for _, u := range h.Upstreams {
		upstreams = append(upstreams, obj{"dial": u.Dial()})
		if u.Scheme == "https" {
			useTLS = true
			skipVerify = skipVerify || u.SkipTLSVerify
		}
	}
	p := obj{"handler": "reverse_proxy", "upstreams": upstreams}
	if len(upstreams) > 1 {
		p["load_balancing"] = obj{"selection_policy": obj{"policy": h.LoadBalancing}}
	}
	if useTLS {
		tls := obj{}
		if skipVerify {
			tls["insecure_skip_verify"] = true
		}
		p["transport"] = obj{"protocol": "http", "tls": tls}
	}
	return p
}

func redirectToHTTPSRoute(h store.Host) obj {
	return obj{
		"@id":   fmt.Sprintf("cpm_host_%d_redirect", h.ID),
		"match": []any{obj{"host": h.Domains}},
		"handle": []any{obj{
			"handler":     "static_response",
			"status_code": "308",
			"headers":     obj{"Location": []string{"https://{http.request.host}{http.request.uri}"}},
		}},
		"terminal": true,
	}
}

func notConfiguredRoute(server string) obj {
	return obj{
		"@id": "cpm_not_configured_" + server,
		"handle": []any{obj{
			"handler":     "static_response",
			"status_code": "404",
			"headers":     obj{"Content-Type": []string{"text/plain; charset=utf-8"}},
			"body":        notConfiguredBody,
		}},
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
