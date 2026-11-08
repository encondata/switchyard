package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/encondata/switchyard/internal/geoip"
)

// ConflictError means an action can't be done in the current state, for
// example deleting a folder that still has hosts. The text is user-facing.
type ConflictError string

func (e ConflictError) Error() string { return string(e) }

// Folder groups hosts. Folders nest, and hosts inherit the access policies
// of their folder and every folder above it (spec F3).
type Folder struct {
	ID        int64   `json:"id"`
	Name      string  `json:"name"`
	ParentID  *int64  `json:"parent_id"`
	Sort      int     `json:"sort"`
	PolicyIDs []int64 `json:"policy_ids"`
	HostCount int     `json:"host_count"`
	// DNSProviderID is the default DNS provider for hosts inside (and in
	// subfolders) that use the DNS challenge without picking one.
	DNSProviderID *int64 `json:"dns_provider_id"`
	// Default headers for hosts inside (applied before the host's own).
	RequestHeaders  []HeaderRule `json:"request_headers"`
	ResponseHeaders []HeaderRule `json:"response_headers"`
	// Default rate limit for hosts inside without their own (0 = none).
	RateLimitEvents int `json:"rate_limit_events"`
	RateLimitWindow int `json:"rate_limit_window"`
}

// Access policy modes and responses (spec F4).
const (
	PolicyAllowOnly = "allow_only"
	PolicyDeny      = "deny"
	Respond403      = "403"
	RespondAbort    = "abort"
)

// AccessPolicy is a named list of IP/CIDR rules.
type AccessPolicy struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	Mode     string   `json:"mode"`
	Response string   `json:"response"`
	Rules    []string `json:"rules"`
	Notes    string   `json:"notes"`
	// Usage counts, filled by ListPolicies.
	FolderCount int `json:"folder_count"`
	HostCount   int `json:"host_count"`
}

// NeverBan is an address that no rule ever blocks.
type NeverBan struct {
	CIDR      string    `json:"cidr"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

var countryRE = regexp.MustCompile(`^[A-Za-z]{2}$`)

// ParseRule turns a rule into its canonical form: a bare address for single
// IPs, a masked prefix for ranges ("10.1.2.3/8" becomes "10.0.0.0/8"), or an
// upper-case ISO country code ("de" becomes "DE").
func ParseRule(raw string) (string, error) {
	r := strings.TrimSpace(raw)
	if countryRE.MatchString(r) {
		if !geoip.ValidCountry(r) {
			return "", fmt.Errorf("%q isn't an ISO country code", r)
		}
		return strings.ToUpper(r), nil
	}
	if strings.Contains(r, "/") {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			return "", fmt.Errorf("%q is not a valid CIDR range", r)
		}
		if p.Addr().Is4In6() {
			// ::ffff:a.b.c.d/n would never match an IPv4 client in Caddy;
			// store the IPv4 range it means instead.
			if p.Bits() < 96 {
				return "", fmt.Errorf("%q mixes IPv6 and IPv4-mapped addresses; write the IPv4 range instead", r)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		p = p.Masked()
		if p.Bits() == p.Addr().BitLen() {
			return p.Addr().String(), nil
		}
		return p.String(), nil
	}
	a, err := netip.ParseAddr(r)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP address or CIDR range", r)
	}
	return a.Unmap().WithZone("").String(), nil
}

// --- folders ---

// ListFolders returns every folder with its policies and direct host count.
func (s *Store) ListFolders(ctx context.Context) ([]Folder, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.id, f.name, f.parent_id, f.sort, f.dns_provider_id, f.request_headers, f.response_headers,
			f.rate_limit_events, f.rate_limit_window,
			(SELECT COUNT(*) FROM hosts h WHERE h.folder_id = f.id)
		FROM folders f ORDER BY f.sort, f.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	out := []Folder{}
	byID := map[int64]int{}
	for rows.Next() {
		var f Folder
		var parent, dnsProvider sql.NullInt64
		var reqH, respH string
		if err := rows.Scan(&f.ID, &f.Name, &parent, &f.Sort, &dnsProvider, &reqH, &respH,
			&f.RateLimitEvents, &f.RateLimitWindow, &f.HostCount); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if parent.Valid {
			f.ParentID = &parent.Int64
		}
		if dnsProvider.Valid {
			f.DNSProviderID = &dnsProvider.Int64
		}
		f.RequestHeaders, f.ResponseHeaders = decodeHeaders(reqH), decodeHeaders(respH)
		f.PolicyIDs = []int64{}
		byID[f.ID] = len(out)
		out = append(out, f)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	links, err := s.db.QueryContext(ctx, `SELECT folder_id, policy_id FROM folder_policies ORDER BY folder_id, policy_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = links.Close() }()
	for links.Next() {
		var fid, pid int64
		if err := links.Scan(&fid, &pid); err != nil {
			return nil, err
		}
		if i, ok := byID[fid]; ok {
			out[i].PolicyIDs = append(out[i].PolicyIDs, pid)
		}
	}
	return out, links.Err()
}

// GetFolder returns one folder.
func (s *Store) GetFolder(ctx context.Context, id int64) (Folder, error) {
	folders, err := s.ListFolders(ctx)
	if err != nil {
		return Folder{}, err
	}
	for _, f := range folders {
		if f.ID == id {
			return f, nil
		}
	}
	return Folder{}, ErrNotFound
}

// SaveFolder creates (ID 0) or updates a folder: its name, parent and
// attached policies.
func (s *Store) SaveFolder(ctx context.Context, f Folder, username string) (Folder, error) {
	f.Name = strings.TrimSpace(f.Name)
	f.PolicyIDs = uniqueIDs(f.PolicyIDs)
	if f.ParentID != nil && *f.ParentID <= 0 {
		f.ParentID = nil
	}
	if f.DNSProviderID != nil && *f.DNSProviderID <= 0 {
		f.DNSProviderID = nil
	}
	errs := ValidationError{}
	if f.Name == "" {
		errs["name"] = "enter a name"
	} else if len(f.Name) > 100 {
		errs["name"] = "keep the name under 100 characters"
	}
	f.RequestHeaders, f.ResponseHeaders = normalizeHeaders(f.RequestHeaders), normalizeHeaders(f.ResponseHeaders)
	if msg := validateHeaders(f.RequestHeaders); msg != "" {
		errs["request_headers"] = msg
	}
	if msg := validateHeaders(f.ResponseHeaders); msg != "" {
		errs["response_headers"] = msg
	}
	if f.RateLimitWindow <= 0 {
		f.RateLimitWindow = 60
	}
	if msg := checkRateLimit(f.RateLimitEvents, f.RateLimitWindow); msg != "" {
		errs["rate_limit"] = msg
	}
	if len(errs) > 0 {
		return Folder{}, errs
	}

	var before *Folder
	if f.ID != 0 {
		old, err := s.GetFolder(ctx, f.ID)
		if err != nil {
			return Folder{}, err
		}
		before = &old
	}

	// Check the parent inside the write transaction: SQLite allows one writer
	// at a time (and the pool has one connection), so no other move can slip
	// in between this check and the update.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Folder{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if f.ParentID != nil {
		if err := checkParent(ctx, tx, f.ID, *f.ParentID); err != nil {
			return Folder{}, err
		}
	}
	if err := checkRefs(ctx, tx, nil, f.PolicyIDs); err != nil {
		return Folder{}, err
	}
	if f.DNSProviderID != nil {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_providers WHERE id = ?`, *f.DNSProviderID).Scan(&n); err != nil {
			return Folder{}, err
		}
		if n == 0 {
			return Folder{}, ValidationError{"dns_provider_id": "that DNS provider doesn't exist"}
		}
	}
	if f.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO folders (name, parent_id, sort, dns_provider_id, request_headers, response_headers,
			rate_limit_events, rate_limit_window) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			f.Name, f.ParentID, f.Sort, f.DNSProviderID, encodeHeaders(f.RequestHeaders), encodeHeaders(f.ResponseHeaders),
			f.RateLimitEvents, f.RateLimitWindow)
		if err != nil {
			return Folder{}, folderNameError(err)
		}
		if f.ID, err = res.LastInsertId(); err != nil {
			return Folder{}, err
		}
	} else if _, err := tx.ExecContext(ctx,
		`UPDATE folders SET name = ?, parent_id = ?, sort = ?, dns_provider_id = ?, request_headers = ?,
			response_headers = ?, rate_limit_events = ?, rate_limit_window = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		f.Name, f.ParentID, f.Sort, f.DNSProviderID, encodeHeaders(f.RequestHeaders), encodeHeaders(f.ResponseHeaders),
		f.RateLimitEvents, f.RateLimitWindow, f.ID); err != nil {
		return Folder{}, folderNameError(err)
	}
	if err := setLinks(ctx, tx, "folder_policies", "folder_id", f.ID, f.PolicyIDs); err != nil {
		return Folder{}, err
	}
	action := "create"
	var b any
	if before != nil {
		action, b = "update", before
	}
	if err := audit(ctx, tx, username, action, "folder", f.ID, b, f); err != nil {
		return Folder{}, err
	}
	if err := tx.Commit(); err != nil {
		return Folder{}, err
	}
	return s.GetFolder(ctx, f.ID)
}

func folderNameError(err error) error {
	if strings.Contains(err.Error(), "UNIQUE") {
		return ValidationError{"name": "a folder with this name already exists here"}
	}
	return err
}

// DeleteFolder removes an empty folder.
func (s *Store) DeleteFolder(ctx context.Context, id int64, username string) error {
	f, err := s.GetFolder(ctx, id)
	if err != nil {
		return err
	}
	var children int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM folders WHERE parent_id = ?`, id).Scan(&children); err != nil {
		return err
	}
	if f.HostCount > 0 || children > 0 {
		return ConflictError(fmt.Sprintf("“%s” still has %d host(s) and %d folder(s). Move them out first.", f.Name, f.HostCount, children))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM folders WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, username, "delete", "folder", id, f, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// SetFolderEnabled enables or disables every host in a folder and the
// folders below it, and returns how many hosts changed.
func (s *Store) SetFolderEnabled(ctx context.Context, id int64, enabled bool, username string) (int, error) {
	if _, err := s.GetFolder(ctx, id); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		WITH RECURSIVE tree(id) AS (
			SELECT ? UNION SELECT f.id FROM folders f JOIN tree ON f.parent_id = tree.id
		)
		UPDATE hosts SET enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE folder_id IN (SELECT id FROM tree) AND enabled != ?`, id, enabled, enabled)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	action := "disable_all"
	if enabled {
		action = "enable_all"
	}
	if err := audit(ctx, tx, username, action, "folder", id, nil, map[string]int64{"hosts_changed": n}); err != nil {
		return 0, err
	}
	return int(n), tx.Commit()
}

// MoveHost puts a host in a folder (nil for Unfiled).
func (s *Store) MoveHost(ctx context.Context, hostID int64, folderID *int64, username string, isAdmin bool) (Host, error) {
	h, err := s.GetHost(ctx, hostID)
	if err != nil {
		return Host{}, err
	}
	h.FolderID = folderID
	return s.SaveHostAs(ctx, h, username, isAdmin)
}

// --- policies ---

// ListPolicies returns every policy with how many folders and hosts use it.
func (s *Store) ListPolicies(ctx context.Context) ([]AccessPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.id, p.name, p.mode, p.response, p.rules, p.notes,
			(SELECT COUNT(*) FROM folder_policies fp WHERE fp.policy_id = p.id),
			(SELECT COUNT(*) FROM host_policies hp WHERE hp.policy_id = p.id)
		FROM access_policies p ORDER BY p.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []AccessPolicy{}
	for rows.Next() {
		var p AccessPolicy
		var rules string
		if err := rows.Scan(&p.ID, &p.Name, &p.Mode, &p.Response, &rules, &p.Notes, &p.FolderCount, &p.HostCount); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(rules), &p.Rules); err != nil {
			return nil, fmt.Errorf("policy %d: bad rules JSON: %w", p.ID, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPolicy returns one policy.
func (s *Store) GetPolicy(ctx context.Context, id int64) (AccessPolicy, error) {
	all, err := s.ListPolicies(ctx)
	if err != nil {
		return AccessPolicy{}, err
	}
	for _, p := range all {
		if p.ID == id {
			return p, nil
		}
	}
	return AccessPolicy{}, ErrNotFound
}

// MaxRules caps the rules in one policy.
const MaxRules = 1000

// SavePolicy creates (ID 0) or updates a policy.
func (s *Store) SavePolicy(ctx context.Context, p AccessPolicy, username string) (AccessPolicy, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Response == "" {
		p.Response = Respond403
	}
	errs := ValidationError{}
	if p.Name == "" {
		errs["name"] = "enter a name"
	} else if len(p.Name) > 100 {
		errs["name"] = "keep the name under 100 characters"
	}
	if strings.ContainsAny(p.Name, "{}\\") {
		errs["name"] = "can't contain { } or \\"
	}
	if p.Mode != PolicyAllowOnly && p.Mode != PolicyDeny {
		errs["mode"] = "choose allow-only or deny"
	}
	if p.Response != Respond403 && p.Response != RespondAbort {
		errs["response"] = "choose 403 or abort"
	}
	rules := []string{}
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if strings.TrimSpace(r) == "" {
			continue
		}
		c, err := ParseRule(r)
		if err != nil {
			errs["rules"] = err.Error()
			break
		}
		if !seen[c] {
			seen[c] = true
			rules = append(rules, c)
		}
	}
	switch {
	case errs["rules"] != "":
	case len(rules) == 0:
		errs["rules"] = "add at least one IP address or CIDR range"
	case len(rules) > MaxRules:
		errs["rules"] = fmt.Sprintf("a policy can have at most %d rules", MaxRules)
	}
	if len(errs) > 0 {
		return AccessPolicy{}, errs
	}
	p.Rules = rules
	rulesJSON, _ := json.Marshal(rules)

	var before *AccessPolicy
	if p.ID != 0 {
		old, err := s.GetPolicy(ctx, p.ID)
		if err != nil {
			return AccessPolicy{}, err
		}
		before = &old
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if p.ID == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO access_policies (name, mode, response, rules, notes) VALUES (?, ?, ?, ?, ?)`,
			p.Name, p.Mode, p.Response, string(rulesJSON), p.Notes)
		if err != nil {
			return AccessPolicy{}, policyNameError(err)
		}
		if p.ID, err = res.LastInsertId(); err != nil {
			return AccessPolicy{}, err
		}
	} else if _, err := tx.ExecContext(ctx, `UPDATE access_policies SET name = ?, mode = ?, response = ?, rules = ?,
		notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, p.Name, p.Mode, p.Response, string(rulesJSON), p.Notes, p.ID); err != nil {
		return AccessPolicy{}, policyNameError(err)
	}
	action := "create"
	var b any
	if before != nil {
		action, b = "update", before
	}
	if err := audit(ctx, tx, username, action, "access_policy", p.ID, b, p); err != nil {
		return AccessPolicy{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccessPolicy{}, err
	}
	return s.GetPolicy(ctx, p.ID)
}

func policyNameError(err error) error {
	if strings.Contains(err.Error(), "UNIQUE") {
		return ValidationError{"name": "a policy with this name already exists"}
	}
	return err
}

// DeletePolicy removes a policy that nothing uses.
func (s *Store) DeletePolicy(ctx context.Context, id int64, username string) error {
	p, err := s.GetPolicy(ctx, id)
	if err != nil {
		return err
	}
	if p.FolderCount > 0 || p.HostCount > 0 {
		return ConflictError(fmt.Sprintf("“%s” is attached to %d folder(s) and %d host(s). Detach it first.", p.Name, p.FolderCount, p.HostCount))
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM access_policies WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, username, "delete", "access_policy", id, p, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// --- never-ban list ---

// ListNeverBan returns the never-block list.
func (s *Store) ListNeverBan(ctx context.Context) ([]NeverBan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cidr, note, created_at FROM never_ban ORDER BY cidr`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []NeverBan{}
	for rows.Next() {
		var n NeverBan
		if err := rows.Scan(&n.CIDR, &n.Note, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// IsCountryRule reports whether a canonical rule is a country code.
func IsCountryRule(r string) bool { return countryRE.MatchString(r) }

// AddNeverBan adds an IP or CIDR to the never-block list.
func (s *Store) AddNeverBan(ctx context.Context, cidr, note, username string) (NeverBan, error) {
	c, err := ParseRule(cidr)
	if err == nil && IsCountryRule(c) {
		err = fmt.Errorf("the never-block list takes IP addresses and ranges, not countries")
	}
	if err != nil {
		return NeverBan{}, ValidationError{"cidr": err.Error()}
	}
	note = strings.TrimSpace(note)
	if len(note) > 200 {
		return NeverBan{}, ValidationError{"note": "keep the note under 200 characters"}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NeverBan{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO never_ban (cidr, note) VALUES (?, ?)`, c, note); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY KEY") {
			return NeverBan{}, ValidationError{"cidr": c + " is already on the list"}
		}
		return NeverBan{}, err
	}
	if err := audit(ctx, tx, username, "create", "never_ban", 0, nil, map[string]string{"cidr": c, "note": note}); err != nil {
		return NeverBan{}, err
	}
	if err := tx.Commit(); err != nil {
		return NeverBan{}, err
	}
	return NeverBan{CIDR: c, Note: note, CreatedAt: time.Now().UTC()}, nil
}

// DeleteNeverBan removes an entry from the never-block list.
func (s *Store) DeleteNeverBan(ctx context.Context, cidr, username string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM never_ban WHERE cidr = ?`, cidr)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := audit(ctx, tx, username, "delete", "never_ban", 0, map[string]string{"cidr": cidr}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// --- resolving what applies to a host ---

// AccessState is everything the compiler needs to work out a host's rules.
type AccessState struct {
	Folders  map[int64]Folder
	Policies map[int64]AccessPolicy
	NeverBan []string
	Honeypot HoneypotState
	CrowdSec CrowdSecSettings
}

// LoadAccessState reads folders, policies and the never-block list.
func (s *Store) LoadAccessState(ctx context.Context) (AccessState, error) {
	st := AccessState{Folders: map[int64]Folder{}, Policies: map[int64]AccessPolicy{}, NeverBan: []string{}}
	folders, err := s.ListFolders(ctx)
	if err != nil {
		return st, err
	}
	for _, f := range folders {
		st.Folders[f.ID] = f
	}
	policies, err := s.ListPolicies(ctx)
	if err != nil {
		return st, err
	}
	for _, p := range policies {
		st.Policies[p.ID] = p
	}
	nb, err := s.ListNeverBan(ctx)
	if err != nil {
		return st, err
	}
	for _, n := range nb {
		st.NeverBan = append(st.NeverBan, n.CIDR)
	}
	if st.Honeypot, err = s.LoadHoneypotState(ctx); err != nil {
		return st, err
	}
	st.CrowdSec, err = s.CrowdSec(ctx)
	return st, err
}

// InheritedPolicy is a policy that applies to a host, and where it came from.
type InheritedPolicy struct {
	AccessPolicy
	// FromFolderID is the folder it was inherited from; nil if attached to
	// the host directly.
	FromFolderID *int64 `json:"from_folder_id"`
}

// EffectivePolicies returns the policies that apply to a host: its own,
// then its folder's, then each parent folder's up to the top. Each policy
// appears once, at its nearest source.
func (st AccessState) EffectivePolicies(h Host) []InheritedPolicy {
	out := []InheritedPolicy{}
	seen := map[int64]bool{}
	add := func(ids []int64, from *int64) {
		for _, id := range ids {
			p, ok := st.Policies[id]
			if !ok || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, InheritedPolicy{AccessPolicy: p, FromFolderID: from})
		}
	}
	add(h.PolicyIDs, nil)
	visited := map[int64]bool{}
	for fid := h.FolderID; fid != nil && !visited[*fid]; {
		visited[*fid] = true
		f, ok := st.Folders[*fid]
		if !ok {
			break
		}
		id := f.ID
		add(f.PolicyIDs, &id)
		fid = f.ParentID
	}
	return out
}

// EffectiveHeaders returns the header rules for a host: folder defaults
// from the top folder down, then the host's own. Later rules win.
func (st AccessState) EffectiveHeaders(h Host) (request, response []HeaderRule) {
	var chain []Folder
	visited := map[int64]bool{}
	for fid := h.FolderID; fid != nil && !visited[*fid]; {
		visited[*fid] = true
		f, ok := st.Folders[*fid]
		if !ok {
			break
		}
		chain = append(chain, f)
		fid = f.ParentID
	}
	for i := len(chain) - 1; i >= 0; i-- {
		request = append(request, chain[i].RequestHeaders...)
		response = append(response, chain[i].ResponseHeaders...)
	}
	request = append(request, h.RequestHeaders...)
	response = append(response, h.ResponseHeaders...)
	return request, response
}

// EffectiveRateLimit returns the host's rate limit, or the nearest
// folder's; ok is false if none applies.
func (st AccessState) EffectiveRateLimit(h Host) (events, window int, ok bool) {
	if h.RateLimitEvents > 0 {
		return h.RateLimitEvents, h.RateLimitWindow, true
	}
	visited := map[int64]bool{}
	for fid := h.FolderID; fid != nil && !visited[*fid]; {
		visited[*fid] = true
		f, found := st.Folders[*fid]
		if !found {
			break
		}
		if f.RateLimitEvents > 0 {
			return f.RateLimitEvents, f.RateLimitWindow, true
		}
		fid = f.ParentID
	}
	return 0, 0, false
}

// EffectiveDNSProvider returns the DNS provider a host uses for the DNS
// challenge: its own, else the nearest folder's default. ok is false if
// there is none.
func (st AccessState) EffectiveDNSProvider(h Host) (id int64, ok bool) {
	if h.DNSProviderID != nil {
		return *h.DNSProviderID, true
	}
	return st.folderDNSProvider(h.FolderID)
}

func (st AccessState) folderDNSProvider(folderID *int64) (int64, bool) {
	visited := map[int64]bool{}
	for fid := folderID; fid != nil && !visited[*fid]; {
		visited[*fid] = true
		f, ok := st.Folders[*fid]
		if !ok {
			break
		}
		if f.DNSProviderID != nil {
			return *f.DNSProviderID, true
		}
		fid = f.ParentID
	}
	return 0, false
}

// checkDNSProvider makes sure a DNS-challenge host has a provider, either
// its own or from its folders.
func checkDNSProvider(ctx context.Context, tx *sql.Tx, h Host) error {
	if h.TLSMode != TLSDNS {
		return nil
	}
	if h.DNSProviderID != nil {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_providers WHERE id = ?`, *h.DNSProviderID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ValidationError{"dns_provider_id": "that DNS provider doesn't exist"}
		}
		return nil
	}
	// Walk up the folders for a default.
	seen := map[int64]bool{}
	for fid := h.FolderID; fid != nil && !seen[*fid]; {
		seen[*fid] = true
		var parent, provider sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT parent_id, dns_provider_id FROM folders WHERE id = ?`, *fid).Scan(&parent, &provider)
		if err != nil {
			break
		}
		if provider.Valid {
			return nil
		}
		if !parent.Valid {
			break
		}
		p := parent.Int64
		fid = &p
	}
	return ValidationError{"dns_provider_id": "choose a DNS provider (or set a default on the host's folder)"}
}

// --- helpers ---

func uniqueIDs(ids []int64) []int64 {
	out := []int64{}
	seen := map[int64]bool{}
	for _, id := range ids {
		if id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
}

func queryIDs(ctx context.Context, db querier, q string, args ...any) ([]int64, error) {
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// setLinks replaces the policy links of one folder or host.
func setLinks(ctx context.Context, tx *sql.Tx, table, ownerCol string, ownerID int64, policyIDs []int64) error {
	// table and ownerCol are constants from this package, never user input.
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE `+ownerCol+` = ?`, ownerID); err != nil { //nolint:gosec // see above
		return err
	}
	for _, pid := range policyIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO `+table+` (`+ownerCol+`, policy_id) VALUES (?, ?)`, ownerID, pid); err != nil { //nolint:gosec // see above
			return err
		}
	}
	return nil
}

// checkParent fails if parentID doesn't exist, or if it is folderID itself
// or one of its descendants (which would make a cycle). The walk stops at
// any folder it has already seen, so existing bad data can't loop forever.
func checkParent(ctx context.Context, tx *sql.Tx, folderID, parentID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, parent_id FROM folders`)
	if err != nil {
		return err
	}
	parentOf := map[int64]*int64{}
	for rows.Next() {
		var id int64
		var parent sql.NullInt64
		if err := rows.Scan(&id, &parent); err != nil {
			_ = rows.Close()
			return err
		}
		if parent.Valid {
			p := parent.Int64
			parentOf[id] = &p
		} else {
			parentOf[id] = nil
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, ok := parentOf[parentID]; !ok {
		return ValidationError{"parent_id": "that folder doesn't exist"}
	}
	seen := map[int64]bool{}
	for p := &parentID; p != nil && !seen[*p]; p = parentOf[*p] {
		if folderID != 0 && *p == folderID {
			return ValidationError{"parent_id": "a folder can't be moved inside itself"}
		}
		seen[*p] = true
	}
	return nil
}

// checkRefs turns a missing folder or policy into a validation error
// instead of a foreign-key failure.
func checkRefs(ctx context.Context, tx *sql.Tx, folderID *int64, policyIDs []int64) error {
	var n int
	if folderID != nil {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM folders WHERE id = ?`, *folderID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ValidationError{"folder_id": "that folder doesn't exist"}
		}
	}
	for _, id := range policyIDs {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_policies WHERE id = ?`, id).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ValidationError{"policy_ids": fmt.Sprintf("policy #%d doesn't exist", id)}
		}
	}
	return nil
}
