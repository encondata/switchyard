package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Host types.
const (
	HostProxy    = "proxy"
	HostRedirect = "redirect"
	Host404      = "404"
)

// TLS modes.
const (
	TLSAuto     = "auto"     // Let's Encrypt / ZeroSSL via HTTP or TLS-ALPN challenge
	TLSInternal = "internal" // Caddy's local CA, for LAN-only names
	TLSOff      = "off"      // plain HTTP on port 80 only
	TLSDNS      = "dns"      // Let's Encrypt via the DNS-01 challenge (wildcards, internal names)
)

// Host is a site CPM serves: a reverse proxy, a redirect or a fixed 404.
type Host struct {
	ID            int64      `json:"id"`
	Type          string     `json:"type"`
	Domains       []string   `json:"domains"`
	Enabled       bool       `json:"enabled"`
	Upstreams     []Upstream `json:"upstreams"`
	LoadBalancing string     `json:"load_balancing"` // round_robin | first
	TLSMode       string     `json:"tls_mode"`
	ForceHTTPS    bool       `json:"force_https"`
	HSTS          bool       `json:"hsts"`
	Compression   bool       `json:"compression"`
	RedirectTo    string     `json:"redirect_to"`
	RedirectCode  int        `json:"redirect_code"`
	PreservePath  bool       `json:"preserve_path"`
	Notes         string     `json:"notes"`
	// FolderID is the folder the host sits in; nil means "Unfiled".
	FolderID *int64 `json:"folder_id"`
	// PolicyIDs are access policies attached to the host itself. The host
	// also gets its folders' policies (see EffectivePolicies).
	PolicyIDs []int64 `json:"policy_ids"`
	// DNSProviderID picks the DNS provider for TLS "dns"; nil means use the
	// nearest folder's default.
	DNSProviderID *int64 `json:"dns_provider_id"`
	// RequestHeaders change headers sent to the upstream (proxy hosts);
	// ResponseHeaders change headers sent to the client. Folder defaults
	// are applied first, so a host rule for the same header wins.
	RequestHeaders  []HeaderRule `json:"request_headers"`
	ResponseHeaders []HeaderRule `json:"response_headers"`
	// HealthCheckPath turns on active health checks of the upstreams
	// ("" = off), every HealthCheckInterval seconds.
	HealthCheckPath     string `json:"health_check_path"`
	HealthCheckInterval int    `json:"health_check_interval"`
	// AdvancedJSON is a raw array of Caddy routes placed after the access
	// rules and before the host's own handler. Admins only.
	AdvancedJSON string    `json:"advanced_json"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Upstream is a backend a proxy host forwards to.
type Upstream struct {
	Scheme        string `json:"scheme"` // http | https
	Host          string `json:"host"`
	Port          int    `json:"port"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
}

// Dial returns the host:port Caddy dials.
func (u Upstream) Dial() string {
	return net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
}

// ValidationError lists problems with a host, keyed by field.
type ValidationError map[string]string

func (v ValidationError) Error() string {
	parts := make([]string, 0, len(v))
	for k, msg := range v {
		parts = append(parts, k+": "+msg)
	}
	return "invalid host: " + strings.Join(parts, "; ")
}

var (
	labelRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	upstreamRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Normalize fills defaults and tidies input before validation.
func (h *Host) Normalize() {
	h.Type = strings.TrimSpace(h.Type)
	if h.Type == "" {
		h.Type = HostProxy
	}
	if h.TLSMode == "" {
		h.TLSMode = TLSAuto
	}
	if h.LoadBalancing == "" {
		h.LoadBalancing = "round_robin"
	}
	if h.RedirectCode == 0 {
		h.RedirectCode = 301
	}
	var domains []string
	for _, d := range h.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" {
			domains = append(domains, d)
		}
	}
	h.Domains = domains
	for i := range h.Upstreams {
		u := &h.Upstreams[i]
		u.Scheme = strings.ToLower(strings.TrimSpace(u.Scheme))
		if u.Scheme == "" {
			u.Scheme = "http"
		}
		if u.Scheme != "https" {
			u.SkipTLSVerify = false // meaningless without TLS
		}
		u.Host = strings.TrimSpace(u.Host)
		if u.Port == 0 {
			if u.Scheme == "https" {
				u.Port = 443
			} else {
				u.Port = 80
			}
		}
	}
	if h.Type != HostProxy {
		h.Upstreams = nil
	}
	if h.Upstreams == nil {
		h.Upstreams = []Upstream{}
	}
	h.RedirectTo = strings.TrimSpace(h.RedirectTo)
	h.PolicyIDs = uniqueIDs(h.PolicyIDs)
	if h.FolderID != nil && *h.FolderID <= 0 {
		h.FolderID = nil
	}
	if h.TLSMode != TLSDNS || (h.DNSProviderID != nil && *h.DNSProviderID <= 0) {
		h.DNSProviderID = nil
	}
	h.RequestHeaders = normalizeHeaders(h.RequestHeaders)
	h.ResponseHeaders = normalizeHeaders(h.ResponseHeaders)
	h.HealthCheckPath = strings.TrimSpace(h.HealthCheckPath)
	if h.HealthCheckInterval <= 0 {
		h.HealthCheckInterval = 30
	}
	if h.Type != HostProxy {
		h.RequestHeaders = []HeaderRule{}
		h.HealthCheckPath = ""
	}
	if h.TLSMode == TLSOff {
		h.ForceHTTPS = false
		h.HSTS = false
	}
}

// Validate checks a normalized host on its own (not against other hosts).
func (h *Host) Validate() error {
	errs := ValidationError{}
	switch h.Type {
	case HostProxy, HostRedirect, Host404:
	default:
		errs["type"] = "must be proxy, redirect or 404"
	}
	switch h.TLSMode {
	case TLSAuto, TLSInternal, TLSOff, TLSDNS:
	default:
		errs["tls_mode"] = "must be auto, dns, internal or off"
	}
	if len(h.Domains) == 0 {
		errs["domains"] = "add at least one domain"
	}
	seen := map[string]bool{}
	for _, d := range h.Domains {
		if seen[d] {
			errs["domains"] = d + " is listed twice"
			break
		}
		seen[d] = true
		if msg := checkDomain(d, h.TLSMode); msg != "" {
			errs["domains"] = msg
			break
		}
	}
	switch h.Type {
	case HostProxy:
		if len(h.Upstreams) == 0 {
			errs["upstreams"] = "add at least one upstream"
		}
		for _, u := range h.Upstreams {
			if u.Scheme != "http" && u.Scheme != "https" {
				errs["upstreams"] = "scheme must be http or https"
			} else if u.Host == "" || !upstreamRE.MatchString(u.Host) && net.ParseIP(u.Host) == nil {
				errs["upstreams"] = fmt.Sprintf("%q is not a valid host name or IP address", u.Host)
			} else if u.Port < 1 || u.Port > 65535 {
				errs["upstreams"] = "port must be between 1 and 65535"
			}
		}
		// Caddy uses one transport for all of a host's upstreams, so TLS and
		// certificate checking can't differ between them.
		for _, u := range h.Upstreams[min(1, len(h.Upstreams)):] {
			first := h.Upstreams[0]
			if u.Scheme != first.Scheme {
				errs["upstreams"] = "all upstreams of a host must use the same scheme (all http or all https)"
			} else if u.SkipTLSVerify != first.SkipTLSVerify {
				errs["upstreams"] = "skip TLS verify must be the same for all upstreams of a host"
			}
		}
		if h.LoadBalancing != "round_robin" && h.LoadBalancing != "first" {
			errs["load_balancing"] = "must be round_robin or first"
		}
	case HostRedirect:
		u, err := url.Parse(h.RedirectTo)
		switch {
		case err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			errs["redirect_to"] = "enter a full URL, like https://example.com"
		case strings.ContainsAny(h.RedirectTo, "{}"):
			// Caddy would expand {…} as a placeholder in the Location header.
			errs["redirect_to"] = "can't contain { or }; percent-encode them as %7B and %7D"
		}
		switch h.RedirectCode {
		case 301, 302, 307, 308:
		default:
			errs["redirect_code"] = "must be 301, 302, 307 or 308"
		}
	}
	if msg := validateHeaders(h.RequestHeaders); msg != "" {
		errs["request_headers"] = msg
	}
	if msg := validateHeaders(h.ResponseHeaders); msg != "" {
		errs["response_headers"] = msg
	}
	if h.HealthCheckPath != "" {
		if !strings.HasPrefix(h.HealthCheckPath, "/") || strings.ContainsAny(h.HealthCheckPath, " {}\r\n") {
			errs["health_check_path"] = "enter a path starting with /, like /health"
		}
		if h.HealthCheckInterval < 5 || h.HealthCheckInterval > 3600 {
			errs["health_check_interval"] = "check every 5 to 3600 seconds"
		}
	}
	if canon, err := ValidateAdvancedJSON(h.AdvancedJSON); err != nil {
		errs["advanced_json"] = err.Error()
	} else {
		h.AdvancedJSON = canon
	}
	if len(h.Notes) > 2000 {
		errs["notes"] = "keep notes under 2000 characters"
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func checkDomain(d, tlsMode string) string {
	if len(d) > 253 {
		return d + " is too long"
	}
	name := d
	if strings.HasPrefix(d, "*.") {
		if tlsMode == TLSAuto {
			return "wildcard domains need the DNS challenge: set the certificate to “DNS challenge”"
		}
		name = d[2:]
	}
	if net.ParseIP(name) != nil {
		return d + ": use a domain name, not an IP address"
	}
	for _, label := range strings.Split(name, ".") {
		if !labelRE.MatchString(label) {
			return d + " is not a valid domain name"
		}
	}
	return ""
}

// ErrDomainTaken is wrapped when a domain already belongs to another host.
var ErrDomainTaken = errors.New("domain already used by another host")

const hostColumns = `id, type, enabled, upstreams, load_balancing, tls_mode, force_https, hsts,
	compression, redirect_to, redirect_code, preserve_path, notes, folder_id, acme_challenge, dns_provider_id,
	request_headers, response_headers, health_check_path, health_check_interval, advanced_json, created_at, updated_at`

func scanHost(row interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var upstreams string
	var folder, dnsProvider sql.NullInt64
	var challenge, reqHeaders, respHeaders string
	err := row.Scan(&h.ID, &h.Type, &h.Enabled, &upstreams, &h.LoadBalancing, &h.TLSMode, &h.ForceHTTPS,
		&h.HSTS, &h.Compression, &h.RedirectTo, &h.RedirectCode, &h.PreservePath, &h.Notes, &folder,
		&challenge, &dnsProvider, &reqHeaders, &respHeaders, &h.HealthCheckPath, &h.HealthCheckInterval,
		&h.AdvancedJSON, &h.CreatedAt, &h.UpdatedAt)
	if err != nil {
		return h, err
	}
	if folder.Valid {
		h.FolderID = &folder.Int64
	}
	if dnsProvider.Valid {
		h.DNSProviderID = &dnsProvider.Int64
	}
	if h.TLSMode == TLSAuto && challenge == "dns" {
		h.TLSMode = TLSDNS
	}
	h.RequestHeaders = decodeHeaders(reqHeaders)
	h.ResponseHeaders = decodeHeaders(respHeaders)
	h.PolicyIDs = []int64{}
	if err := json.Unmarshal([]byte(upstreams), &h.Upstreams); err != nil {
		return h, fmt.Errorf("host %d: bad upstreams JSON: %w", h.ID, err)
	}
	return h, nil
}

// ListHosts returns all hosts with their domains, ordered by first domain.
func (s *Store) ListHosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostColumns+` FROM hosts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var hosts []Host
	byID := map[int64]int{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		h.Domains = []string{}
		byID[h.ID] = len(hosts)
		hosts = append(hosts, h)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	drows, err := s.db.QueryContext(ctx, `SELECT host_id, domain FROM host_domains ORDER BY host_id, position`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = drows.Close() }()
	for drows.Next() {
		var id int64
		var d string
		if err := drows.Scan(&id, &d); err != nil {
			return nil, err
		}
		if i, ok := byID[id]; ok {
			hosts[i].Domains = append(hosts[i].Domains, d)
		}
	}
	if err := drows.Err(); err != nil {
		return nil, err
	}
	if hosts == nil {
		return []Host{}, nil
	}
	prows, err := s.db.QueryContext(ctx, `SELECT host_id, policy_id FROM host_policies ORDER BY host_id, policy_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = prows.Close() }()
	for prows.Next() {
		var hid, pid int64
		if err := prows.Scan(&hid, &pid); err != nil {
			return nil, err
		}
		if i, ok := byID[hid]; ok {
			hosts[i].PolicyIDs = append(hosts[i].PolicyIDs, pid)
		}
	}
	return hosts, prows.Err()
}

// GetHost returns one host.
func (s *Store) GetHost(ctx context.Context, id int64) (Host, error) {
	h, err := scanHost(s.db.QueryRowContext(ctx, `SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrNotFound
	}
	if err != nil {
		return Host{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM host_domains WHERE host_id = ? ORDER BY position`, id)
	if err != nil {
		return Host{}, err
	}
	defer func() { _ = rows.Close() }()
	h.Domains = []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return Host{}, err
		}
		h.Domains = append(h.Domains, d)
	}
	if err := rows.Err(); err != nil {
		return Host{}, err
	}
	h.PolicyIDs, err = queryIDs(ctx, s.db, `SELECT policy_id FROM host_policies WHERE host_id = ? ORDER BY policy_id`, id)
	return h, err
}

// SaveHost creates (ID 0) or updates a host as an admin, after normalizing
// and validating it, and records the change in the audit log.
func (s *Store) SaveHost(ctx context.Context, h Host, username string) (Host, error) {
	return s.SaveHostAs(ctx, h, username, true)
}

// ErrAdvancedAdminOnly is returned when a non-admin tries to change a host
// that has an advanced JSON snippet, or to change the snippet itself.
var ErrAdvancedAdminOnly = ConflictError("This host has advanced JSON, so only admins can change it.")

// SaveHostAs saves a host for a user who may not be an admin. Non-admins
// can't set or change advanced JSON, and can't change hosts that have it
// (that would let them reuse an admin's snippet on other domains or
// upstreams). The check uses the row read inside the write transaction.
func (s *Store) SaveHostAs(ctx context.Context, h Host, username string, isAdmin bool) (Host, error) {
	h.Normalize()
	if err := h.Validate(); err != nil {
		return Host{}, err
	}
	var before *Host
	if h.ID != 0 {
		old, err := s.GetHost(ctx, h.ID)
		if err != nil {
			return Host{}, err
		}
		before = &old
	}
	upstreams, err := json.Marshal(h.Upstreams)
	if err != nil {
		return Host{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Host{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if !isAdmin {
		current := ""
		if h.ID != 0 {
			if err := tx.QueryRowContext(ctx, `SELECT advanced_json FROM hosts WHERE id = ?`, h.ID).Scan(&current); err != nil {
				return Host{}, err
			}
		}
		if current != "" || h.AdvancedJSON != "" {
			return Host{}, ErrAdvancedAdminOnly
		}
	}
	if err := checkRefs(ctx, tx, h.FolderID, h.PolicyIDs); err != nil {
		return Host{}, err
	}
	if err := checkDNSProvider(ctx, tx, h); err != nil {
		return Host{}, err
	}

	// DNS is stored as tls_mode 'auto' + acme_challenge 'dns' (see 0004).
	tlsMode, challenge := h.TLSMode, "http"
	if h.TLSMode == TLSDNS {
		tlsMode, challenge = TLSAuto, "dns"
	}
	args := []any{h.Type, h.Enabled, string(upstreams), h.LoadBalancing, tlsMode, h.ForceHTTPS, h.HSTS,
		h.Compression, h.RedirectTo, h.RedirectCode, h.PreservePath, h.Notes, h.FolderID, challenge, h.DNSProviderID,
		encodeHeaders(h.RequestHeaders), encodeHeaders(h.ResponseHeaders), h.HealthCheckPath, h.HealthCheckInterval,
		h.AdvancedJSON}
	if h.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO hosts (type, enabled, upstreams, load_balancing, tls_mode,
			force_https, hsts, compression, redirect_to, redirect_code, preserve_path, notes, folder_id,
			acme_challenge, dns_provider_id, request_headers, response_headers, health_check_path,
			health_check_interval, advanced_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
		if err != nil {
			return Host{}, err
		}
		if h.ID, err = res.LastInsertId(); err != nil {
			return Host{}, err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET type = ?, enabled = ?, upstreams = ?, load_balancing = ?,
			tls_mode = ?, force_https = ?, hsts = ?, compression = ?, redirect_to = ?, redirect_code = ?,
			preserve_path = ?, notes = ?, folder_id = ?, acme_challenge = ?, dns_provider_id = ?,
			request_headers = ?, response_headers = ?, health_check_path = ?, health_check_interval = ?,
			advanced_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			append(args, h.ID)...); err != nil {
			return Host{}, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_domains WHERE host_id = ?`, h.ID); err != nil {
			return Host{}, err
		}
	}
	for i, d := range h.Domains {
		var owner int64
		err := tx.QueryRowContext(ctx, `SELECT host_id FROM host_domains WHERE domain = ?`, d).Scan(&owner)
		if err == nil {
			return Host{}, ValidationError{"domains": fmt.Sprintf("%s is already used by host #%d", d, owner)}
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Host{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_domains (domain, host_id, position) VALUES (?, ?, ?)`,
			d, h.ID, i); err != nil {
			return Host{}, err
		}
	}
	if err := setLinks(ctx, tx, "host_policies", "host_id", h.ID, h.PolicyIDs); err != nil {
		return Host{}, err
	}
	action := "create"
	if before != nil {
		action = "update"
	}
	if err := audit(ctx, tx, username, action, "host", h.ID, before, h); err != nil {
		return Host{}, err
	}
	if err := tx.Commit(); err != nil {
		return Host{}, err
	}
	return s.GetHost(ctx, h.ID)
}

// DeleteHost removes a host.
func (s *Store) DeleteHost(ctx context.Context, id int64, username string) error {
	before, err := s.GetHost(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, username, "delete", "host", id, before, nil); err != nil {
		return err
	}
	return tx.Commit()
}

func audit(ctx context.Context, tx *sql.Tx, username, action, entity string, id int64, before, after any) error {
	enc := func(v any) string {
		if v == nil {
			return ""
		}
		switch x := v.(type) {
		case *Host:
			if x == nil {
				return ""
			}
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_log (username, action, entity, entity_id, before, after)
		VALUES (?, ?, ?, ?, ?, ?)`, username, action, entity, strconv.FormatInt(id, 10), enc(before), enc(after))
	return err
}
