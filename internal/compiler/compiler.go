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
//   - access rules (spec F4) sit at the top of each host's subroute, in
//     order: deny policies, then allow-only policies. Every block route
//     carries "not: never-ban", so never-ban addresses skip all rules.
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
	"strings"

	"github.com/encondata/caddyproxymanager/internal/store"
)

// Settings are the parts of the config that don't come from hosts.
type Settings struct {
	// AdminListen is Caddy's admin listener, e.g. "unix//run/caddy/admin.sock|0660".
	AdminListen string
	// SecretsDir is where DNS provider tokens are written as files, as seen
	// by Caddy. The config refers to them with {file.…} placeholders, so
	// tokens never appear in the config, its history or diffs.
	SecretsDir string
	// ACMECA overrides the ACME directory (e.g. Let's Encrypt staging or a
	// Pebble test server). Empty means Caddy's defaults.
	ACMECA string
	// ACMEEmail is the contact address for ACME accounts (optional).
	ACMEEmail string
	// GeoIPDB is the GeoLite2-Country database path as Caddy sees it;
	// GeoIPReady says whether it exists. Country rules need both.
	GeoIPDB    string
	GeoIPReady bool
	// AccessLogFile, if set, makes Caddy write a JSON access log of every
	// request there, which CPM ingests for the dashboard (spec F5).
	AccessLogFile string
	// TLSLogFile, if set, makes Caddy also write its certificate
	// management logs there as JSON, so CPM can show why a certificate
	// failed (spec F2).
	TLSLogFile string
}

// CrowdSecKeyFile is the file holding the CrowdSec bouncer key.
func CrowdSecKeyFile(dir string) string { return strings.TrimRight(dir, "/") + "/crowdsec.key" }

// DNSTokenFile is the file holding a DNS provider's token.
func DNSTokenFile(dir string, providerID int64) string {
	return fmt.Sprintf("%s/dns-%d.token", strings.TrimRight(dir, "/"), providerID)
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
func Compile(s Settings, hosts []store.Host, access store.AccessState) ([]byte, error) {
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
	dnsSubjects := map[int64][]string{}
	for _, h := range enabled {
		if h.TLSMode == store.TLSDNS {
			pid, ok := access.EffectiveDNSProvider(h)
			if !ok {
				return nil, fmt.Errorf("compiler: host %d (%s) uses the DNS challenge but has no DNS provider", h.ID, strings.Join(h.Domains, ", "))
			}
			dnsSubjects[pid] = append(dnsSubjects[pid], h.Domains...)
		}
		route, err := hostRoute(h, access, s)
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
			plain, _ := hostRoute(h, access, s) // same handlers, also on :80
			plain["@id"] = fmt.Sprintf("cpm_host_%d_http", h.ID)
			httpRoutes = append(httpRoutes, plain)
		}
		if h.TLSMode == store.TLSInternal {
			internalSubjects = append(internalSubjects, h.Domains...)
		}
	}
	hp := access.Honeypot
	if hp.Settings.Enabled {
		httpRoutes = append(httpRoutes, catchallRoute("http", hp.Settings.Response))
		httpsRoutes = append(httpsRoutes, catchallRoute("https", hp.Settings.Response))
		internalSubjects = append(internalSubjects, HoneypotSNI)
	} else {
		httpRoutes = append(httpRoutes, notConfiguredRoute("http"))
		httpsRoutes = append(httpsRoutes, notConfiguredRoute("https"))
	}
	// CrowdSec community block lists (optional), checked after CPM's bans.
	crowdsec := access.CrowdSec.Enabled && access.CrowdSec.KeySet && s.SecretsDir != ""
	// Every request first: tag the user agent for the access log, then the
	// ban list (spec F4 step 2; it comes after the never-ban check).
	head := func(server string) []any {
		var r []any
		if s.AccessLogFile != "" {
			r = append(r, obj{"handle": []any{obj{
				"handler": "log_append", "key": "user_agent", "value": "{http.request.header.User-Agent}", "early": true,
			}}})
		}
		r = append(r, banRoute(server, hp.Bans, access.NeverBan))
		if crowdsec {
			cs := obj{"handle": []any{obj{"handler": "crowdsec"}}}
			if len(access.NeverBan) > 0 {
				cs["match"] = []any{obj{"not": []any{obj{"client_ip": obj{"ranges": access.NeverBan}}}}}
			}
			r = append(r, cs)
		}
		return r
	}
	httpRoutes = append(head("http"), httpRoutes...)
	httpsRoutes = append(head("https"), httpsRoutes...)

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
					HTTPSServer: httpsServer(httpsRoutes, hp.Settings.Enabled),
				},
			},
			// The internal CA's root can't be installed into a container's
			// trust store; don't try.
			"pki": obj{"certificate_authorities": obj{"local": obj{"install_trust": false}}},
		},
	}
	var policies []any
	providerIDs := make([]int64, 0, len(dnsSubjects))
	for id := range dnsSubjects {
		providerIDs = append(providerIDs, id)
	}
	sort.Slice(providerIDs, func(i, j int) bool { return providerIDs[i] < providerIDs[j] })
	if len(providerIDs) > 0 && s.SecretsDir == "" {
		return nil, fmt.Errorf("compiler: DNS challenge hosts need a secrets directory (CPM_SECRETS_DIR)")
	}
	for _, id := range providerIDs {
		iss := acmeIssuer(s)
		iss["challenges"] = obj{"dns": obj{
			"provider": obj{
				"name":      "cloudflare",
				"api_token": "{file." + DNSTokenFile(s.SecretsDir, id) + "}",
			},
			// Public resolvers see the TXT record even where local DNS is
			// split-horizon (common for internal names).
			"resolvers": []string{"1.1.1.1", "1.0.0.1"},
		}}
		policies = append(policies, obj{"subjects": dnsSubjects[id], "issuers": []any{iss}})
	}
	if len(internalSubjects) > 0 {
		policies = append(policies, obj{
			"subjects": internalSubjects,
			"issuers":  []any{obj{"module": "internal"}},
		})
	}
	if s.ACMECA != "" || s.ACMEEmail != "" {
		// Catch-all for HTTP-challenge hosts.
		policies = append(policies, obj{"issuers": []any{acmeIssuer(s)}})
	}
	if len(policies) > 0 {
		cfg["apps"].(obj)["tls"] = obj{"automation": obj{"policies": policies}}
	}
	if crowdsec {
		cfg["apps"].(obj)["crowdsec"] = obj{
			"api_url":          access.CrowdSec.APIURL,
			"api_key":          "{file." + CrowdSecKeyFile(s.SecretsDir) + "}",
			"ticker_interval":  "15s",
			"enable_streaming": true,
		}
	}
	if hp.Settings.Enabled {
		// Make sure the honeypot's internal-CA certificate exists even though
		// no host matcher names it.
		tlsApp, _ := cfg["apps"].(obj)["tls"].(obj)
		if tlsApp == nil {
			tlsApp = obj{}
			cfg["apps"].(obj)["tls"] = tlsApp
		}
		tlsApp["certificates"] = obj{"automate": []string{HoneypotSNI}}
	}
	logs := obj{}
	if s.TLSLogFile != "" {
		logs["cpm_tls"] = obj{
			"writer":  obj{"output": "file", "filename": s.TLSLogFile, "roll_size_mb": 5, "roll_keep": 2},
			"encoder": obj{"format": "json"},
			"include": []string{"tls.obtain", "tls.renew", "tls.issuance"},
		}
	}
	if s.AccessLogFile != "" {
		servers := cfg["apps"].(obj)["http"].(obj)["servers"].(obj)
		for _, name := range []string{HTTPServer, HTTPSServer} {
			servers[name].(obj)["logs"] = obj{"default_logger_name": "cpm_access"}
		}
		logs["cpm_access"] = obj{
			"writer": obj{"output": "file", "filename": s.AccessLogFile, "roll_size_mb": 100, "roll_keep": 3},
			// Keep secrets out of the file: no query strings (they can hold
			// tokens) and no headers (cookies, auth). The user agent comes in
			// its own field (see the first route of each server).
			"encoder": obj{
				"format": "filter",
				"wrap":   obj{"format": "json"},
				"fields": obj{
					"request>headers": obj{"filter": "delete"},
					"resp_headers":    obj{"filter": "delete"},
					"request>uri":     obj{"filter": "regexp", "regexp": `\?.*$`, "value": ""},
				},
			},
			"include": []string{"http.log.access.cpm_access"},
		}
		// Keep access logs out of Caddy's stderr log.
		logs["default"] = obj{"exclude": []string{"http.log.access.cpm_access"}}
	}
	if len(logs) > 0 {
		cfg["logging"] = obj{"logs": logs}
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

func acmeIssuer(s Settings) obj {
	iss := obj{"module": "acme"}
	if s.ACMECA != "" {
		iss["ca"] = s.ACMECA
	}
	if s.ACMEEmail != "" {
		iss["email"] = s.ACMEEmail
	}
	return iss
}

func hostRoute(h store.Host, access store.AccessState, s Settings) (obj, error) {
	// Header handlers go in their own route before the advanced snippet, so
	// they also cover responses the snippet produces.
	var headerHandlers, handlers []any
	if h.HSTS && h.TLSMode != store.TLSOff {
		headerHandlers = append(headerHandlers, obj{
			"handler":  "headers",
			"response": obj{"set": obj{"Strict-Transport-Security": []string{"max-age=31536000"}}},
		})
	}
	reqHeaders, respHeaders := access.EffectiveHeaders(h)
	if ops := headerOps(respHeaders); ops != nil {
		// Deferred, so the rules also apply to headers the upstream sets.
		ops["deferred"] = true
		headerHandlers = append(headerHandlers, obj{"handler": "headers", "response": ops})
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
		p := proxyHandler(h)
		if ops := headerOps(reqHeaders); ops != nil {
			p["headers"] = obj{"request": ops}
		}
		handlers = append(handlers, p)
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
	// Access rules always come first, so the advanced snippet can't bypass
	// them; then the snippet; then the host's own handlers.
	subroutes, err := accessRoutes(h, access, s)
	if err != nil {
		return nil, err
	}
	if access.Honeypot.Settings.Enabled {
		subroutes = append(subroutes, trapRoutes(h, access.Honeypot)...)
	}
	if len(headerHandlers) > 0 {
		subroutes = append(subroutes, obj{"handle": headerHandlers})
	}
	if events, window, ok := access.EffectiveRateLimit(h); ok {
		zone := obj{"key": "{http.request.remote.host}", "window": fmt.Sprintf("%ds", window), "max_events": events}
		if len(access.NeverBan) > 0 {
			// Never-block addresses aren't rate limited either.
			zone["match"] = []any{obj{"not": []any{obj{"client_ip": obj{"ranges": access.NeverBan}}}}}
		}
		subroutes = append(subroutes, obj{"handle": []any{obj{"handler": "rate_limit", "rate_limits": obj{"cpm": zone}}}})
	}
	if h.AdvancedJSON != "" {
		var adv []any
		if err := json.Unmarshal([]byte(h.AdvancedJSON), &adv); err != nil {
			return nil, fmt.Errorf("advanced JSON: %w", err)
		}
		subroutes = append(subroutes, adv...)
	}
	subroutes = append(subroutes, obj{"handle": handlers})
	return obj{
		"@id":      fmt.Sprintf("cpm_host_%d", h.ID),
		"match":    []any{obj{"host": h.Domains}},
		"handle":   []any{obj{"handler": "subroute", "routes": subroutes}},
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
	if h.HealthCheckPath != "" {
		p["health_checks"] = obj{
			"active": obj{
				"uri":      h.HealthCheckPath,
				"interval": fmt.Sprintf("%ds", h.HealthCheckInterval),
				"timeout":  "5s",
			},
			// Also stop sending traffic to an upstream that just failed.
			"passive": obj{"fail_duration": "30s"},
		}
	}
	return p
}

// headerOps folds header rules, in order, into Caddy's header operations.
// Caddy applies add, then set, then delete, so a later rule for a header
// replaces earlier rules for the same header.
func headerOps(rules []store.HeaderRule) obj {
	if len(rules) == 0 {
		return nil
	}
	type state struct {
		op     string
		values []string
	}
	order := []string{}
	byName := map[string]*state{}
	for _, r := range rules {
		key := strings.ToLower(r.Name)
		st, ok := byName[key]
		if !ok {
			st = &state{}
			byName[key] = st
			order = append(order, r.Name)
		}
		switch r.Op {
		case "set", "delete":
			st.op, st.values = r.Op, nil
			if r.Op == "set" {
				st.values = []string{r.Value}
			}
		case "add":
			// After a set, keep it a set with both values (Caddy would
			// otherwise apply the set after the add and drop the added value).
			// After a delete, start over with just this value.
			switch st.op {
			case "delete", "":
				st.op, st.values = "add", nil
			}
			st.values = append(st.values, r.Value)
		}
	}
	set, add := obj{}, obj{}
	var del []string
	for _, name := range order {
		st := byName[strings.ToLower(name)]
		switch st.op {
		case "set":
			set[name] = st.values
		case "add":
			add[name] = st.values
		case "delete":
			del = append(del, name)
		}
	}
	ops := obj{}
	if len(set) > 0 {
		ops["set"] = set
	}
	if len(add) > 0 {
		ops["add"] = add
	}
	if len(del) > 0 {
		ops["delete"] = del
	}
	if len(ops) == 0 {
		return nil
	}
	return ops
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

// HoneypotSNI is the name of the honeypot's internal-CA certificate, used
// for TLS connections to names CPM doesn't serve (and bare-IP requests).
// It is under .invalid, so it can never be a real, public name.
const HoneypotSNI = "cpm-honeypot.invalid"

// BanListID is the @id of each server's ban list route, which CPM updates
// in place when bans change (spec §2, principle 4).
func BanListID(server string) string { return "cpm_banlist_" + server }

// noMatchRange keeps the ban list's matcher valid when nobody is banned;
// no client can connect from 0.0.0.0.
const noMatchRange = "0.0.0.0/32"

// BanMatch is the ban list route's matcher for the given bans.
func BanMatch(bans, never []string) []any {
	ranges := bans
	if len(ranges) == 0 {
		ranges = []string{noMatchRange}
	}
	m := obj{"client_ip": obj{"ranges": ranges}}
	if len(never) > 0 {
		m["not"] = []any{obj{"client_ip": obj{"ranges": never}}}
	}
	return []any{m}
}

func banRoute(server string, bans, never []string) obj {
	return obj{
		"@id":   BanListID(server),
		"match": BanMatch(bans, never),
		"handle": []any{
			obj{"handler": "log_append", "key": "cpm_blocked", "value": "banned", "early": true},
			obj{"handler": "static_response", "abort": true},
		},
		"terminal": true,
	}
}

func httpsServer(routes []any, honeypot bool) obj {
	srv := obj{
		"listen":          []string{":443"},
		"routes":          routes,
		"automatic_https": obj{"disable_redirects": true},
	}
	if honeypot {
		// Unknown names and bare-IP requests get the honeypot certificate,
		// so the catch-all can answer them over HTTPS too.
		srv["tls_connection_policies"] = []any{obj{"fallback_sni": HoneypotSNI, "default_sni": HoneypotSNI}}
	}
	return srv
}

// honeypotHandlers tag the request for the scorer and serve fake,
// static content (nothing is executed and no upstream is reached).
func honeypotHandlers(reason, response string) []any {
	h := []any{obj{"handler": "log_append", "key": "cpm_honeypot", "value": reason, "early": true}}
	switch response {
	case "server":
		h = append(h, obj{
			"handler": "static_response", "status_code": "200",
			"headers": obj{"Content-Type": []string{"text/html; charset=utf-8"}, "Server": []string{"Apache/2.4.41 (Ubuntu)"}},
			"body":    fakeServerPage,
		})
	case "empty":
		h = append(h, obj{"handler": "static_response", "status_code": "200"})
	case "404":
		h = append(h, obj{"handler": "static_response", "status_code": "404", "body": "Not Found\n"})
	default: // login
		h = append(h, obj{
			"handler": "static_response", "status_code": "200",
			"headers": obj{"Content-Type": []string{"text/html; charset=utf-8"}, "Server": []string{"nginx"}},
			"body":    fakeLoginPage,
		})
	}
	return h
}

const fakeLoginPage = `<!doctype html><html><head><title>Sign in</title></head><body style="font-family:sans-serif">` +
	`<form method="post" action="#" style="max-width:280px;margin:10% auto"><h2>Administrator sign in</h2>` +
	`<p><input name="username" placeholder="Username"></p><p><input name="password" type="password" placeholder="Password"></p>` +
	`<p><button>Sign in</button></p></form></body></html>`

const fakeServerPage = `<!doctype html><html><head><title>Apache2 Ubuntu Default Page: It works</title></head>` +
	`<body><h1>It works!</h1><p>This is the default welcome page used to test the correct operation of the Apache2 server.</p></body></html>`

func catchallRoute(server, response string) obj {
	return obj{"@id": "cpm_catchall_" + server, "handle": honeypotHandlers("catchall", response)}
}

// trapRoutes send known scanner paths on a host to the honeypot: one
// route per distinct score, tagged "trap:<score>", so the scorer uses the
// score of the trap Caddy actually matched (Caddy's path matching is
// case-insensitive and works on the cleaned path).
func trapRoutes(h store.Host, hp store.HoneypotState) []any {
	skip := map[string]bool{}
	for _, e := range h.TrapExceptions {
		skip[e] = true
	}
	byScore := map[int][]string{}
	for _, t := range hp.Traps {
		if !skip[t.Pattern] {
			byScore[t.Score] = append(byScore[t.Score], t.Pattern)
		}
	}
	scores := make([]int, 0, len(byScore))
	for sc := range byScore {
		scores = append(scores, sc)
	}
	// Highest score first, so a path matching several traps scores the most.
	sort.Sort(sort.Reverse(sort.IntSlice(scores)))
	var routes []any
	for _, sc := range scores {
		routes = append(routes, obj{
			"match":    []any{obj{"path": byScore[sc]}},
			"handle":   honeypotHandlers(fmt.Sprintf("trap:%d", sc), hp.Settings.Response),
			"terminal": true,
		})
	}
	return routes
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

// accessRoutes returns the block routes for a host's effective policies.
//
// Evaluation order (spec F4): never-ban → allow; deny match → block;
// allow-only rules exist and none match → block; otherwise allow. Bans
// (step 2) come from the honeypot. Rules are IPs/CIDRs (client_ip matcher)
// or ISO country codes (maxmind_geolocation matcher).
func accessRoutes(h store.Host, access store.AccessState, s Settings) ([]any, error) {
	var never []any
	if len(access.NeverBan) > 0 {
		never = []any{obj{"client_ip": obj{"ranges": access.NeverBan}}}
	}
	countryMatcher := func(codes []string) (obj, error) {
		if s.GeoIPDB == "" || !s.GeoIPReady {
			return nil, fmt.Errorf("host %d (%s) has country rules, but the GeoLite2 database isn't installed (see the GeoIP section of the README)",
				h.ID, strings.Join(h.Domains, ", "))
		}
		return obj{"maxmind_geolocation": obj{"db_path": s.GeoIPDB, "allow_countries": codes}}, nil
	}
	var routes []any
	var allowIPs, allowCountries []string
	allowResponse := store.Respond403
	for _, p := range access.EffectivePolicies(h) {
		ips, countries := splitRules(p.Rules)
		switch p.Mode {
		case store.PolicyDeny:
			var sets []any
			if len(ips) > 0 {
				sets = append(sets, obj{"client_ip": obj{"ranges": ips}})
			}
			if len(countries) > 0 {
				m, err := countryMatcher(countries)
				if err != nil {
					return nil, err
				}
				sets = append(sets, m)
			}
			for _, set := range sets {
				if never != nil {
					set.(obj)["not"] = never
				}
			}
			// The tag is placeholder-expanded by Caddy, so it holds only IDs;
			// CPM shows the policy name when reading the log.
			routes = append(routes, obj{"match": sets, "handle": blockHandlers(p.Response, fmt.Sprintf("deny:policy:%d", p.ID))})
		case store.PolicyAllowOnly:
			allowIPs = append(allowIPs, ips...)
			allowCountries = append(allowCountries, countries...)
			if p.Response == store.RespondAbort {
				allowResponse = store.RespondAbort // the stricter response wins
			}
		}
	}
	if len(allowIPs) > 0 || len(allowCountries) > 0 {
		// Block when the client matches none of: allowed ranges, allowed
		// countries, never-ban list. not(A OR B OR C).
		var sets []any
		if len(allowIPs) > 0 {
			sets = append(sets, obj{"client_ip": obj{"ranges": dedupe(allowIPs)}})
		}
		if len(allowCountries) > 0 {
			m, err := countryMatcher(dedupe(allowCountries))
			if err != nil {
				return nil, err
			}
			sets = append(sets, m)
		}
		sets = append(sets, never...)
		routes = append(routes, obj{"match": []any{obj{"not": sets}}, "handle": blockHandlers(allowResponse, "not_allowed")})
	}
	return routes, nil
}

func splitRules(rules []string) (ips, countries []string) {
	for _, r := range rules {
		if store.IsCountryRule(r) {
			countries = append(countries, r)
		} else {
			ips = append(ips, r)
		}
	}
	return ips, countries
}

// blockHandlers tags the access log entry with why the request was
// blocked (read by the log ingester), then responds.
func blockHandlers(response, reason string) []any {
	return []any{
		// early: add the field before responding, so it's logged even
		// when the connection is dropped (abort).
		obj{"handler": "log_append", "key": "cpm_blocked", "value": reason, "early": true},
		blockHandler(response),
	}
}

func blockHandler(response string) obj {
	if response == store.RespondAbort {
		return obj{"handler": "static_response", "abort": true}
	}
	return obj{
		"handler":     "static_response",
		"status_code": "403",
		"headers":     obj{"Content-Type": []string{"text/plain; charset=utf-8"}},
		"body":        "Access denied.\n",
	}
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
