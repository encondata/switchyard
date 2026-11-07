// Package npmimport reads an Nginx Proxy Manager database (SQLite or
// MySQL) and turns its hosts and access lists into CPM hosts and policies
// (spec F7, CPM-20). Imported hosts go into an "Imported" folder, disabled
// until someone reviews them. Anything CPM can't convert is reported.
package npmimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	// MySQL driver for NPM installs that use MySQL/MariaDB.
	"github.com/go-sql-driver/mysql"

	"github.com/encondata/caddyproxymanager/internal/store"
)

// FolderName is where imported hosts go.
const FolderName = "Imported"

// PlannedHost is a CPM host the import will create.
type PlannedHost struct {
	Source   string     `json:"source"` // e.g. "proxy_host #12"
	Host     store.Host `json:"host"`
	Policies []string   `json:"policies"` // names of planned policies to attach
	Warnings []string   `json:"warnings"`
	Skip     string     `json:"skip,omitempty"` // reason it won't be imported
}

// PlannedPolicy is a CPM access policy made from an NPM access list.
type PlannedPolicy struct {
	Source string             `json:"source"`
	Policy store.AccessPolicy `json:"policy"`
}

// Stream is an NPM TCP/UDP stream (not imported; see CPM-33).
type Stream struct {
	ID           int64  `json:"id"`
	IncomingPort int64  `json:"incoming_port"`
	Forward      string `json:"forward"`
	Protocols    string `json:"protocols"`
	Enabled      bool   `json:"enabled"`
}

// Plan is what an import would do.
type Plan struct {
	Hosts    []PlannedHost   `json:"hosts"`
	Policies []PlannedPolicy `json:"policies"`
	Streams  []Stream        `json:"streams"`
	Warnings []string        `json:"warnings"`
}

// Result is what an import did.
type Result struct {
	FolderID        int64    `json:"folder_id"`
	HostsCreated    int      `json:"hosts_created"`
	PoliciesCreated int      `json:"policies_created"`
	Skipped         []string `json:"skipped"`
}

// OpenSQLite opens an NPM database.sqlite file read-only.
func OpenSQLite(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?mode=ro")
}

// MySQLConfig is how to reach an NPM MySQL/MariaDB database.
type MySQLConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// OpenMySQL connects to an NPM MySQL database.
func OpenMySQL(c MySQLConfig) (*sql.DB, error) {
	if c.Port == 0 {
		c.Port = 3306
	}
	if c.Host == "" || c.User == "" || c.Database == "" {
		return nil, fmt.Errorf("enter the host, user and database name")
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd = c.User, c.Password
	cfg.Net, cfg.Addr, cfg.DBName = "tcp", netJoin(c.Host, c.Port), c.Database
	cfg.Timeout, cfg.ReadTimeout = 10*time.Second, 30*time.Second
	dsn := cfg.FormatDSN()
	return sql.Open("mysql", dsn)
}

func netJoin(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

// row is one database row by column name. Reading by name copes with the
// column changes across NPM versions.
type row map[string]any

func (r row) str(k string) string {
	switch v := r[k].(type) {
	case nil:
		return ""
	case []byte:
		return string(v)
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func (r row) int(k string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(r.str(k)), 10, 64)
	return n
}

func (r row) bool(k string) bool { return r.int(k) != 0 || r.str(k) == "true" }

func (r row) has(k string) bool { _, ok := r[k]; return ok }

func (r row) strings(k string) []string {
	var out []string
	_ = json.Unmarshal([]byte(r.str(k)), &out)
	return out
}

func (r row) meta() map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal([]byte(r.str("meta")), &m)
	return m
}

func readTable(ctx context.Context, db *sql.DB, table string) ([]row, error) {
	// table names are constants from this package.
	rows, err := db.QueryContext(ctx, "SELECT * FROM "+table) //nolint:gosec // constant table names
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []row
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := row{}
		for i, c := range cols {
			r[strings.ToLower(c)] = vals[i]
		}
		if r.bool("is_deleted") {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Options steer the conversion.
type Options struct {
	// DNSProviderID is used for hosts whose NPM certificate used a DNS
	// challenge; 0 if CPM has no DNS provider yet.
	DNSProviderID int64
	// Existing domains in CPM; hosts using them are skipped.
	ExistingDomains map[string]bool
}

// Build reads the NPM database and works out the import.
func Build(ctx context.Context, db *sql.DB, opts Options) (Plan, error) {
	p := Plan{Hosts: []PlannedHost{}, Policies: []PlannedPolicy{}, Streams: []Stream{}, Warnings: []string{}}
	if err := db.PingContext(ctx); err != nil {
		return p, fmt.Errorf("can't open the NPM database: %w", err)
	}
	if _, err := readTable(ctx, db, "proxy_host"); err != nil {
		return p, fmt.Errorf("this doesn't look like an NPM database (no proxy_host table): %w", err)
	}

	certs := map[int64]row{}
	if rows, err := readTable(ctx, db, "certificate"); err == nil {
		for _, r := range rows {
			certs[r.int("id")] = r
		}
	}

	// Access lists → policies.
	listPolicies := map[int64][]string{}
	if lists, err := readTable(ctx, db, "access_list"); err == nil {
		clients, _ := readTable(ctx, db, "access_list_client")
		auths, _ := readTable(ctx, db, "access_list_auth")
		for _, l := range lists {
			id := l.int("id")
			var allow, deny []string
			var bad []string
			for _, c := range clients {
				if c.int("access_list_id") != id {
					continue
				}
				addr := strings.TrimSpace(c.str("address"))
				if addr == "all" {
					continue // "allow/deny all" is the default the other entries imply
				}
				norm, err := store.ParseRule(addr)
				if err != nil {
					bad = append(bad, addr)
					continue
				}
				if c.str("directive") == "deny" {
					deny = append(deny, norm)
				} else {
					allow = append(allow, norm)
				}
			}
			name := "NPM: " + l.str("name")
			if len(allow) > 0 {
				p.Policies = append(p.Policies, PlannedPolicy{
					Source: fmt.Sprintf("access_list #%d", id),
					Policy: store.AccessPolicy{Name: name, Mode: store.PolicyAllowOnly, Response: store.Respond403, Rules: allow,
						Notes: "Imported from NPM access list “" + l.str("name") + "”."},
				})
				listPolicies[id] = append(listPolicies[id], name)
			}
			if len(deny) > 0 {
				dn := name + " (deny)"
				p.Policies = append(p.Policies, PlannedPolicy{
					Source: fmt.Sprintf("access_list #%d", id),
					Policy: store.AccessPolicy{Name: dn, Mode: store.PolicyDeny, Response: store.Respond403, Rules: deny,
						Notes: "Imported from NPM access list “" + l.str("name") + "”."},
				})
				listPolicies[id] = append(listPolicies[id], dn)
			}
			for _, a := range auths {
				if a.int("access_list_id") == id {
					p.Warnings = append(p.Warnings, fmt.Sprintf("Access list “%s” uses basic auth (user %s); CPM doesn't support basic auth yet, so it isn't imported.", l.str("name"), a.str("username")))
				}
			}
			if len(bad) > 0 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("Access list “%s”: skipped entries CPM can't read: %s", l.str("name"), strings.Join(bad, ", ")))
			}
		}
	}

	add := func(table, kind string, conv func(row, *PlannedHost)) error {
		rows, err := readTable(ctx, db, table)
		if err != nil {
			if table == "proxy_host" {
				return err
			}
			return nil // older NPM without this table
		}
		for _, r := range rows {
			ph := PlannedHost{Source: fmt.Sprintf("%s #%d", table, r.int("id")), Warnings: []string{}, Policies: []string{}}
			h := store.Host{Type: kind, Domains: r.strings("domain_names"), Enabled: false}
			tlsFrom(r, certs, opts, &h, &ph)
			h.ForceHTTPS = h.TLSMode != store.TLSOff && r.bool("ssl_forced")
			h.HSTS = h.TLSMode != store.TLSOff && r.bool("hsts_enabled")
			h.Compression = true
			ph.Host = h
			conv(r, &ph)
			if cfg := strings.TrimSpace(r.str("advanced_config")); cfg != "" {
				ph.Warnings = append(ph.Warnings, "Has custom nginx config, which can't be converted. It's copied into the host's notes; recreate it as advanced JSON if needed.")
				ph.Host.Notes = appendNote(ph.Host.Notes, "NPM custom nginx config:\n"+cfg)
			}
			if r.bool("enabled") || !r.has("enabled") {
				ph.Host.Notes = appendNote(ph.Host.Notes, "Was enabled in NPM.")
			} else {
				ph.Host.Notes = appendNote(ph.Host.Notes, "Was disabled in NPM.")
			}
			for _, d := range ph.Host.Domains {
				if opts.ExistingDomains[strings.ToLower(d)] {
					ph.Skip = d + " already exists in CPM"
				}
			}
			ph.Host.Normalize()
			if ph.Skip == "" {
				if err := ph.Host.Validate(); err != nil {
					ph.Skip = err.Error()
				}
			}
			p.Hosts = append(p.Hosts, ph)
		}
		return nil
	}

	if err := add("proxy_host", store.HostProxy, func(r row, ph *PlannedHost) {
		scheme := r.str("forward_scheme")
		if scheme == "" {
			scheme = "http"
		}
		host := r.str("forward_host")
		if host == "" {
			host = r.str("forward_ip") // NPM before 2.0
		}
		ph.Host.Upstreams = []store.Upstream{{Scheme: scheme, Host: host, Port: int(r.int("forward_port"))}}
		if lid := r.int("access_list_id"); lid > 0 {
			ph.Policies = append(ph.Policies, listPolicies[lid]...)
		}
		if locs := strings.TrimSpace(r.str("locations")); locs != "" && locs != "[]" && locs != "null" {
			ph.Warnings = append(ph.Warnings, "Has custom locations, which aren't converted. They're copied into the notes; recreate them as advanced JSON routes if needed.")
			ph.Host.Notes = appendNote(ph.Host.Notes, "NPM custom locations: "+locs)
		}
		if r.bool("caching_enabled") {
			ph.Warnings = append(ph.Warnings, "Asset caching was on in NPM; Caddy doesn't cache by default.")
		}
		if r.bool("block_exploits") {
			ph.Warnings = append(ph.Warnings, "“Block common exploits” was on; CPM's honeypot trap paths cover most of that.")
		}
	}); err != nil {
		return p, err
	}
	_ = add("redirection_host", store.HostRedirect, func(r row, ph *PlannedHost) {
		scheme := r.str("forward_scheme")
		if scheme == "" || scheme == "$scheme" || scheme == "auto" {
			scheme = "https"
		}
		ph.Host.RedirectTo = scheme + "://" + strings.TrimSpace(r.str("forward_domain_name"))
		ph.Host.PreservePath = r.bool("preserve_path")
		code := int(r.int("forward_http_code"))
		switch code {
		case 301, 302, 307, 308:
			ph.Host.RedirectCode = code
		case 0:
			ph.Host.RedirectCode = 301
		default:
			ph.Host.RedirectCode = 302
			ph.Warnings = append(ph.Warnings, fmt.Sprintf("Redirect code %d isn't supported; using 302.", code))
		}
	})
	_ = add("dead_host", store.Host404, func(row, *PlannedHost) {})

	if streams, err := readTable(ctx, db, "stream"); err == nil {
		for _, s := range streams {
			var protos []string
			if s.bool("tcp_forwarding") {
				protos = append(protos, "TCP")
			}
			if s.bool("udp_forwarding") {
				protos = append(protos, "UDP")
			}
			fwd := s.str("forwarding_host")
			if fwd == "" {
				fwd = s.str("forward_ip")
			}
			p.Streams = append(p.Streams, Stream{
				ID: s.int("id"), IncomingPort: s.int("incoming_port"),
				Forward:   fmt.Sprintf("%s:%d", fwd, s.int("forwarding_port")),
				Protocols: strings.Join(protos, "+"), Enabled: s.bool("enabled") || !s.has("enabled"),
			})
		}
		if len(p.Streams) > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("NPM has %d stream(s) (TCP/UDP forwarding). CPM doesn't do streams (see CPM-33); keep them elsewhere or use a VPN.", len(p.Streams)))
		}
	}
	sort.SliceStable(p.Hosts, func(i, j int) bool { return p.Hosts[i].Source < p.Hosts[j].Source })
	return p, nil
}

// tlsFrom picks the TLS mode from the host's NPM certificate.
func tlsFrom(r row, certs map[int64]row, opts Options, h *store.Host, ph *PlannedHost) {
	cid := r.int("certificate_id")
	if cid == 0 {
		h.TLSMode = store.TLSOff
		return
	}
	c, ok := certs[cid]
	if !ok {
		h.TLSMode = store.TLSAuto
		return
	}
	if c.str("provider") == "other" {
		ph.Warnings = append(ph.Warnings, "Used a custom (uploaded) certificate in NPM; CPM will get one from Let's Encrypt instead.")
	}
	meta := c.meta()
	dns, _ := meta["dns_challenge"].(bool)
	wildcard := false
	for _, d := range h.Domains {
		if strings.HasPrefix(d, "*.") {
			wildcard = true
		}
	}
	switch {
	case (dns || wildcard) && opts.DNSProviderID > 0:
		h.TLSMode = store.TLSDNS
		id := opts.DNSProviderID
		h.DNSProviderID = &id
	case dns || wildcard:
		h.TLSMode = store.TLSInternal
		ph.Warnings = append(ph.Warnings, "Used a DNS-challenge certificate in NPM. Add your Cloudflare token on the DNS page, then switch this host to “DNS challenge”; it's set to the internal CA for now.")
	default:
		h.TLSMode = store.TLSAuto
	}
}

func appendNote(notes, add string) string {
	if notes == "" {
		return add
	}
	return notes + "\n\n" + add
}

// Apply creates the planned policies and hosts. Hosts are created
// disabled, in the Imported folder; a host whose save fails is skipped and
// reported.
func Apply(ctx context.Context, st *store.Store, p Plan, username string) (Result, error) {
	res := Result{Skipped: []string{}}
	folderID, err := importFolder(ctx, st, username)
	if err != nil {
		return res, err
	}
	res.FolderID = folderID

	existing, err := st.ListPolicies(ctx)
	if err != nil {
		return res, err
	}
	policyIDs := map[string]int64{}
	for _, ep := range existing {
		policyIDs[strings.ToLower(ep.Name)] = ep.ID
	}
	for _, pp := range p.Policies {
		if _, ok := policyIDs[strings.ToLower(pp.Policy.Name)]; ok {
			continue // imported before; reuse it
		}
		saved, err := st.SavePolicy(ctx, pp.Policy, username)
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("policy “%s”: %v", pp.Policy.Name, err))
			continue
		}
		policyIDs[strings.ToLower(saved.Name)] = saved.ID
		res.PoliciesCreated++
	}
	for _, ph := range p.Hosts {
		if ph.Skip != "" {
			res.Skipped = append(res.Skipped, ph.Source+": "+ph.Skip)
			continue
		}
		h := ph.Host
		h.ID = 0
		h.Enabled = false
		h.FolderID = &folderID
		for _, name := range ph.Policies {
			if id, ok := policyIDs[strings.ToLower(name)]; ok {
				h.PolicyIDs = append(h.PolicyIDs, id)
			}
		}
		if _, err := st.SaveHost(ctx, h, username); err != nil {
			res.Skipped = append(res.Skipped, ph.Source+": "+err.Error())
			continue
		}
		res.HostsCreated++
	}
	return res, nil
}

func importFolder(ctx context.Context, st *store.Store, username string) (int64, error) {
	folders, err := st.ListFolders(ctx)
	if err != nil {
		return 0, err
	}
	for _, f := range folders {
		if f.ParentID == nil && strings.EqualFold(f.Name, FolderName) {
			return f.ID, nil
		}
	}
	f, err := st.SaveFolder(ctx, store.Folder{Name: FolderName}, username)
	return f.ID, err
}
