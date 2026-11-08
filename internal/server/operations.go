package server

import (
	"net/http"

	"github.com/encondata/switchyard/internal/apply"
	"github.com/encondata/switchyard/internal/geoip"
	"github.com/encondata/switchyard/internal/hits"
	"github.com/encondata/switchyard/internal/store"
)

// Who may call an operation with a session (API keys are checked against
// their own permission list instead).
const (
	rolePublic  = ""        // anyone
	rolePending = "pending" // signed in, even before the first password change
	roleViewer  = "viewer"  // signed in
	roleEditor  = "editor"
	roleAdmin   = "admin"
)

// Op is one API operation. The list of them (operations) is the single
// source for routing, API key permissions and the OpenAPI document.
type Op struct {
	ID      string  `json:"id"` // e.g. "hosts.update"; what API key permissions name
	Method  string  `json:"method"`
	Path    string  `json:"path"`
	Area    string  `json:"area"`
	Summary string  `json:"summary"`
	Role    string  `json:"role"`    // minimum session role
	Keyable bool    `json:"keyable"` // API keys may be given this operation
	Write   bool    `json:"write"`   // changes something (vs. only reads)
	Query   []Param `json:"query,omitempty"`

	body, resp any // example types for the OpenAPI schemas
}

// Param is a query parameter.
type Param struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Dependencies an operation's handler needs; routes whose parts aren't
// configured (in tests, say) aren't registered.
const (
	needStore = 1 << iota
	needApply
	needMonitor
	needHits
)

type route struct {
	Op
	needs   int
	handler http.HandlerFunc
}

var scopeParams = []Param{
	{"range", "1h, 24h, 7d or 30d (default 24h)"},
	{"host", "Only this host ID"},
	{"folder", "Only hosts in this folder ID (and its subfolders)"},
}

// Request bodies that handlers decode into unnamed structs, named here so
// the OpenAPI document can describe them.
type (
	neverBanBody struct {
		CIDR string `json:"cidr"`
		Note string `json:"note"`
	}
	dnsProviderBody struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		APIToken string `json:"api_token"`
	}
	banBody struct {
		CIDR   string `json:"cidr"`
		Reason string `json:"reason"`
		Days   int    `json:"days"`
	}
	cidrBody struct {
		CIDR string `json:"cidr"`
	}
	userCreateBody struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	userUpdateBody struct {
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
	}
	passwordBody struct {
		Password string `json:"password"`
	}
	moveBody struct {
		FolderID *int64 `json:"folder_id"`
	}
	enabledBody struct {
		Enabled bool `json:"enabled"`
	}
	noteBody struct {
		Note string `json:"note"`
	}
	crowdSecBody struct {
		Enabled bool   `json:"enabled"`
		APIURL  string `json:"api_url"`
		APIKey  string `json:"api_key"`
	}
	settingsBody struct {
		Require2FA bool `json:"require_2fa"`
	}
	apiKeyBody struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		ExpiresAt   *string  `json:"expires_at"`
	}
)

func (s *srv) routes() []route {
	r := func(needs int, id, method, path, area, role string, keyable, write bool, summary string, h http.HandlerFunc) route {
		return route{Op: Op{ID: id, Method: method, Path: path, Area: area, Summary: summary, Role: role, Keyable: keyable, Write: write}, needs: needs, handler: h}
	}
	with := func(rt route, body, resp any, q ...Param) route {
		rt.body, rt.resp, rt.Query = body, resp, q
		return rt
	}
	st, ap, mo, hi := needStore, needStore|needApply, needStore|needMonitor, needStore|needHits
	return []route{
		// Session and account: people only, never API keys.
		r(st, "auth.login", "POST", "/api/auth/login", "Account", rolePublic, false, true, "Sign in with a username and password", s.handleLogin),
		r(st, "auth.totp", "POST", "/api/auth/totp", "Account", rolePublic, false, true, "Finish signing in with a two-factor code", s.handleLoginTOTP),
		r(st, "auth.logout", "POST", "/api/auth/logout", "Account", rolePublic, false, true, "Sign out", s.handleLogout),
		r(st, "auth.me", "GET", "/api/auth/me", "Account", rolePending, false, false, "The signed-in user", s.handleMe),
		r(st, "auth.password", "POST", "/api/auth/password", "Account", rolePending, false, true, "Change your password", s.handleChangePassword),
		r(st, "auth.preferences.get", "GET", "/api/auth/preferences", "Account", roleViewer, false, false, "Your display preferences", s.handleGetPrefs),
		r(st, "auth.preferences.update", "PUT", "/api/auth/preferences", "Account", roleViewer, false, true, "Save your display preferences", s.handlePutPrefs),
		r(st, "auth.2fa.status", "GET", "/api/auth/2fa", "Account", rolePending, false, false, "Your two-factor sign-in status", s.handle2FAStatus),
		r(st, "auth.2fa.begin", "POST", "/api/auth/2fa/begin", "Account", rolePending, false, true, "Start setting up two-factor sign-in", s.handle2FABegin),
		r(st, "auth.2fa.confirm", "POST", "/api/auth/2fa/confirm", "Account", rolePending, false, true, "Confirm two-factor sign-in with a code", s.handle2FAConfirm),
		r(st, "auth.2fa.disable", "POST", "/api/auth/2fa/disable", "Account", roleViewer, false, true, "Turn off two-factor sign-in", s.handle2FADisable),

		// API keys: admins, with a session. A key can't manage keys.
		r(st, "apikeys.list", "GET", "/api/keys", "API keys", roleAdmin, false, false, "List API keys", s.handleListAPIKeys),
		with(r(st, "apikeys.create", "POST", "/api/keys", "API keys", roleAdmin, false, true, "Make an API key (its token is in the answer, once)", s.handleCreateAPIKey), apiKeyBody{}, nil),
		with(r(st, "apikeys.update", "PUT", "/api/keys/{id}", "API keys", roleAdmin, false, true, "Rename a key or change its permissions", s.handleUpdateAPIKey), apiKeyBody{}, store.APIKey{}),
		r(st, "apikeys.revoke", "POST", "/api/keys/{id}/revoke", "API keys", roleAdmin, false, true, "Revoke a key; it stops working at once", s.handleRevokeAPIKey),
		r(st, "apikeys.operations", "GET", "/api/keys/operations", "API keys", roleAdmin, false, false, "Operations a key can be given", s.handleKeyOperations),

		// Status.
		r(st, "status.get", "GET", "/api/status", "Health", roleViewer, true, false, "Whether Switchyard can reach Caddy", s.handleStatus),
		r(mo, "health.details", "GET", "/api/health/details", "Health", roleViewer, true, false, "Health page: Caddy, applies, drift, disk, GeoIP, alerts", s.handleHealth),
		r(mo, "health.check", "POST", "/api/health/check", "Health", roleViewer, true, true, "Run the health checks now", s.handleCheckNow),
		with(r(mo, "alerts.list", "GET", "/api/alerts", "Health", roleViewer, true, false, "Open alerts (all=1 for resolved ones too)", s.handleAlerts), nil, []store.Alert{}, Param{"all", "1 to include resolved alerts"}),

		// Hosts.
		with(r(ap, "hosts.list", "GET", "/api/hosts", "Hosts", roleViewer, true, false, "List hosts, with certificate status", s.handleListHosts), nil, []hostView{}),
		with(r(ap, "hosts.create", "POST", "/api/hosts", "Hosts", roleEditor, true, true, "Create a host", s.handleSaveHost), store.Host{}, store.Host{}),
		with(r(ap, "hosts.get", "GET", "/api/hosts/{id}", "Hosts", roleViewer, true, false, "Get a host", s.handleGetHost), nil, store.Host{}),
		with(r(ap, "hosts.update", "PUT", "/api/hosts/{id}", "Hosts", roleEditor, true, true, "Replace a host's settings", s.handleSaveHost), store.Host{}, store.Host{}),
		r(ap, "hosts.delete", "DELETE", "/api/hosts/{id}", "Hosts", roleEditor, true, true, "Delete a host", s.handleDeleteHost),
		with(r(ap, "hosts.move", "POST", "/api/hosts/{id}/move", "Hosts", roleEditor, true, true, "Move a host to a folder (null for none)", s.handleMoveHost), moveBody{}, nil),

		// Folders.
		with(r(ap, "folders.list", "GET", "/api/folders", "Folders", roleViewer, true, false, "List folders", s.handleListFolders), nil, []store.Folder{}),
		with(r(ap, "folders.create", "POST", "/api/folders", "Folders", roleEditor, true, true, "Create a folder", s.handleSaveFolder), store.Folder{}, store.Folder{}),
		with(r(ap, "folders.update", "PUT", "/api/folders/{id}", "Folders", roleEditor, true, true, "Replace a folder's settings", s.handleSaveFolder), store.Folder{}, store.Folder{}),
		r(ap, "folders.delete", "DELETE", "/api/folders/{id}", "Folders", roleEditor, true, true, "Delete a folder (its hosts become unfiled)", s.handleDeleteFolder),
		with(r(ap, "folders.enabled", "POST", "/api/folders/{id}/enabled", "Folders", roleEditor, true, true, "Enable or disable every host in a folder", s.handleFolderEnabled), enabledBody{}, nil),

		// Access.
		with(r(ap, "policies.list", "GET", "/api/policies", "Access", roleViewer, true, false, "List access policies", s.handleListPolicies), nil, []store.AccessPolicy{}),
		with(r(ap, "policies.create", "POST", "/api/policies", "Access", roleEditor, true, true, "Create an access policy", s.handleSavePolicy), store.AccessPolicy{}, store.AccessPolicy{}),
		with(r(ap, "policies.update", "PUT", "/api/policies/{id}", "Access", roleEditor, true, true, "Replace an access policy", s.handleSavePolicy), store.AccessPolicy{}, store.AccessPolicy{}),
		r(ap, "policies.delete", "DELETE", "/api/policies/{id}", "Access", roleEditor, true, true, "Delete an access policy", s.handleDeletePolicy),
		with(r(ap, "neverban.list", "GET", "/api/never-ban", "Access", roleViewer, true, false, "List never-block addresses", s.handleListNeverBan), nil, []store.NeverBan{}),
		with(r(ap, "neverban.add", "POST", "/api/never-ban", "Access", roleEditor, true, true, "Never block an IP or CIDR", s.handleAddNeverBan), neverBanBody{}, nil),
		with(r(ap, "neverban.delete", "DELETE", "/api/never-ban", "Access", roleEditor, true, true, "Remove a never-block entry", s.handleDeleteNeverBan), nil, nil, Param{"cidr", "The entry to remove"}),
		r(ap, "access.whoami", "GET", "/api/whoami", "Access", roleViewer, true, false, "The caller's IP as Switchyard sees it", s.handleWhoAmI),
		r(ap, "access.countries", "GET", "/api/countries", "Access", roleViewer, true, false, "ISO country codes and names", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, geoip.Countries())
		}),

		// DNS and certificates.
		with(r(ap, "dns.list", "GET", "/api/dns-providers", "DNS", roleViewer, true, false, "List DNS providers (tokens never shown)", s.handleListDNSProviders), nil, []store.DNSProvider{}),
		with(r(ap, "dns.create", "POST", "/api/dns-providers", "DNS", roleAdmin, true, true, "Add a DNS provider", s.handleSaveDNSProvider), dnsProviderBody{}, store.DNSProvider{}),
		with(r(ap, "dns.update", "PUT", "/api/dns-providers/{id}", "DNS", roleAdmin, true, true, "Change a DNS provider (empty token keeps the old one)", s.handleSaveDNSProvider), dnsProviderBody{}, store.DNSProvider{}),
		r(ap, "dns.delete", "DELETE", "/api/dns-providers/{id}", "DNS", roleAdmin, true, true, "Delete a DNS provider", s.handleDeleteDNSProvider),
		r(ap, "dns.verify", "POST", "/api/dns-providers/{id}/verify", "DNS", roleEditor, true, true, "Check a DNS provider's token with the provider", s.handleVerifyDNSProvider),
		r(ap, "certs.list", "GET", "/api/certificates", "Certificates", roleViewer, true, false, "Certificate status for every domain", s.handleCertificates),
		r(ap, "certs.retry", "POST", "/api/certificates/retry", "Certificates", roleEditor, true, true, "Retry failed certificates now", s.handleRetryCerts),

		// Applying config.
		with(r(ap, "config.preview", "GET", "/api/config/preview", "Config", roleViewer, true, false, "Pending changes: diff against Caddy's running config", s.handlePreview), nil, apply.Preview{}),
		with(r(ap, "config.apply", "POST", "/api/config/apply", "Config", roleEditor, true, true, "Apply pending changes to Caddy", s.handleApply), noteBody{}, store.ConfigVersion{}),
		with(r(ap, "config.versions", "GET", "/api/config/versions", "Config", roleViewer, true, false, "List applied config versions", s.handleListVersions), nil, []store.ConfigVersion{}),
		r(ap, "config.version", "GET", "/api/config/versions/{n}", "Config", roleViewer, true, false, "One applied config version", s.handleGetVersion),
		r(ap, "config.version.diff", "GET", "/api/config/versions/{n}/diff", "Config", roleViewer, true, false, "Diff of a version against the one before", s.handleVersionDiff),
		r(ap, "config.rollback", "POST", "/api/config/versions/{n}/rollback", "Config", roleEditor, true, true, "Roll back to a version", s.handleRollback),

		// Traffic.
		with(r(hi, "stats.overview", "GET", "/api/stats/overview", "Traffic", roleViewer, true, false, "Totals and time series", s.handleStatsOverview), nil, nil, scopeParams...),
		with(r(hi, "stats.top", "GET", "/api/stats/top", "Traffic", roleViewer, true, false, "Busiest IPs, paths, countries, status classes or hosts", s.handleStatsTop), nil, []hits.TopRow{},
			append([]Param{{"dim", "ip, path, country, status or host"}, {"limit", "Rows (default 20, max 100)"}}, scopeParams...)...),
		with(r(hi, "stats.tail", "GET", "/api/stats/tail", "Traffic", roleViewer, true, false, "Newest requests (live view)", s.handleStatsTail), nil, []hits.Hit{},
			append([]Param{{"after", "Only requests with a larger ID"}}, scopeParams...)...),
		r(hi, "stats.ip", "GET", "/api/stats/ip/{ip}", "Traffic", roleViewer, true, false, "One IP's requests, ban and never-block status", s.handleStatsIP),
		with(r(hi, "stats.country", "GET", "/api/stats/country/{code}", "Traffic", roleViewer, true, false, "One country's traffic (ISO code, LAN or unknown)", s.handleStatsCountry), nil, hits.CountryDetail{}, scopeParams...),

		// Honeypot and bans.
		r(hi, "honeypot.get", "GET", "/api/honeypot", "Honeypot", roleViewer, true, false, "Honeypot settings and trap paths", s.handleGetHoneypot),
		with(r(hi, "honeypot.update", "PUT", "/api/honeypot", "Honeypot", roleEditor, true, true, "Change honeypot settings", s.handlePutHoneypot), store.HoneypotSettings{}, store.HoneypotSettings{}),
		with(r(hi, "traps.create", "POST", "/api/honeypot/traps", "Honeypot", roleEditor, true, true, "Add a trap path", s.handleSaveTrap), store.TrapPath{}, store.TrapPath{}),
		with(r(hi, "traps.update", "PUT", "/api/honeypot/traps/{id}", "Honeypot", roleEditor, true, true, "Change a trap path", s.handleSaveTrap), store.TrapPath{}, store.TrapPath{}),
		r(hi, "traps.delete", "DELETE", "/api/honeypot/traps/{id}", "Honeypot", roleEditor, true, true, "Delete a trap path", s.handleDeleteTrap),
		r(hi, "honeypot.activity", "GET", "/api/honeypot/activity", "Honeypot", roleViewer, true, false, "Recent honeypot hits and top sources", s.handleHoneypotActivity),
		with(r(hi, "bans.list", "GET", "/api/bans", "Honeypot", roleViewer, true, false, "List bans (all=1 for lifted and expired too)", s.handleListBans), nil, []store.Ban{}, Param{"all", "1 to include lifted and expired bans"}),
		with(r(hi, "bans.add", "POST", "/api/bans", "Honeypot", roleEditor, true, true, "Ban an IP or CIDR on every host (days 0 = until lifted)", s.handleAddBan), banBody{}, store.Ban{}),
		r(hi, "bans.delete", "DELETE", "/api/bans/{id}", "Honeypot", roleEditor, true, true, "Lift a ban", s.handleRemoveBan),
		with(r(hi, "bans.unban", "POST", "/api/bans/unban", "Honeypot", roleEditor, true, true, "Lift every ban covering an address", s.handleUnbanAddress), cidrBody{}, nil),
		with(r(hi, "bans.export", "GET", "/api/bans/export", "Honeypot", roleViewer, true, false, "Active bans as a block list (format=json for JSON)", s.handleExportBans), nil, nil, Param{"format", "json, or plain text by default"}),
		r(hi, "crowdsec.get", "GET", "/api/crowdsec", "Honeypot", roleAdmin, true, false, "CrowdSec settings (key never shown)", s.handleGetCrowdSec),
		with(r(hi, "crowdsec.update", "PUT", "/api/crowdsec", "Honeypot", roleAdmin, true, true, "Change CrowdSec settings", s.handlePutCrowdSec), crowdSecBody{}, nil),

		// Administration. Keys may read users and the audit log, but not change
		// accounts or the sign-in policy (a key could otherwise make itself an
		// admin person), nor download backups (password hashes, secrets).
		with(r(st, "users.list", "GET", "/api/users", "Users", roleAdmin, true, false, "List users", s.handleListUsers), nil, []store.User{}),
		with(r(st, "users.create", "POST", "/api/users", "Users", roleAdmin, false, true, "Create a user (they choose a new password at first sign-in)", s.handleCreateUser), userCreateBody{}, store.User{}),
		with(r(st, "users.update", "PUT", "/api/users/{id}", "Users", roleAdmin, false, true, "Change a user's role or disable them", s.handleUpdateUser), userUpdateBody{}, store.User{}),
		with(r(st, "users.password", "POST", "/api/users/{id}/password", "Users", roleAdmin, false, true, "Set a temporary password for a user", s.handleResetUserPassword), passwordBody{}, nil),
		r(st, "users.reset2fa", "POST", "/api/users/{id}/reset-2fa", "Users", roleAdmin, false, true, "Turn off a user's two-factor sign-in", s.handleResetUser2FA),
		r(st, "users.delete", "DELETE", "/api/users/{id}", "Users", roleAdmin, false, true, "Delete a user", s.handleDeleteUser),
		with(r(st, "settings.get", "GET", "/api/settings", "Users", roleAdmin, true, false, "Sign-in policy", s.handleGetSettings), nil, nil),
		with(r(st, "settings.update", "PUT", "/api/settings", "Users", roleAdmin, false, true, "Change the sign-in policy", s.handlePutSettings), settingsBody{}, nil),
		with(r(st, "audit.list", "GET", "/api/audit", "Users", roleAdmin, true, false, "Audit log, newest first", s.handleAudit), nil, []store.AuditEntry{},
			Param{"before", "Only entries with a smaller ID (paging)"}, Param{"limit", "Entries (default 100, max 500)"},
			Param{"entity", "Only this kind of thing, e.g. host"}, Param{"user", "Only this user or key"}),
		r(mo, "backup.download", "GET", "/api/backup", "Users", roleAdmin, false, false, "Download a backup of the database (not for keys: it holds password hashes and secrets)", s.handleBackup),
		r(mo, "backup.restore", "POST", "/api/restore", "Users", roleAdmin, false, true, "Restore a backup (replaces everything, API keys included)", s.handleRestore),
		r(mo, "import.preview", "POST", "/api/import/npm/preview", "Import", roleAdmin, true, true, "Read Nginx Proxy Manager and preview an import", s.handleImportPreview),
		r(mo, "import.run", "POST", "/api/import/npm/run", "Import", roleAdmin, true, true, "Run a previewed import", s.handleImportRun),
	}
}

// has reports whether the parts a route needs are configured.
func (s *srv) has(needs int) bool {
	return (needs&needStore == 0 || s.store != nil) &&
		(needs&needApply == 0 || s.apply != nil) &&
		(needs&needMonitor == 0 || s.monitor != nil) &&
		(needs&needHits == 0 || s.hits != nil)
}

// guard puts an operation behind its authentication: a session with the
// operation's role, or an API key that has been given the operation.
func (s *srv) guard(op Op, h http.HandlerFunc) http.HandlerFunc {
	if op.Role == rolePublic {
		return h
	}
	session := s.requireUser(op.Role == rolePending, h)
	switch op.Role {
	case roleEditor:
		session = s.requireEditor(h)
	case roleAdmin:
		session = s.requireAdmin(h)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if token, ok := apiKeyFrom(r); ok {
			s.keyAuth(op, token, h)(w, r)
			return
		}
		session(w, r)
	}
}
