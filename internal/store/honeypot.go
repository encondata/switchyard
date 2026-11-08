package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// HoneypotSettings configure the catch-all host, trap scoring and
// auto-ban (spec F6). Stored as JSON in the settings table.
type HoneypotSettings struct {
	Enabled bool `json:"enabled"`
	// Response is what the honeypot serves: login (fake sign-in page),
	// server (fake default server page), empty (empty 200) or 404.
	Response      string `json:"response"`
	CatchallScore int    `json:"catchall_score"`
	Threshold     int    `json:"threshold"`
	WindowHours   int    `json:"window_hours"`
	BanDays       int    `json:"ban_days"`
	MaxBanDays    int    `json:"max_ban_days"`
	// Abuse bans addresses for how they treat real hosts, honeypot or not.
	Abuse AbuseSettings `json:"abuse"`
}

// AbuseSettings ban an address that, within WindowMinutes, gets at least
// RateLimited rate-limited (429) answers, Blocked requests refused by
// access rules, or NotFound "not found" (404) answers from a host. 0 turns
// that count off. Bans use the honeypot's ban length (doubling for
// repeats); never-block and local network addresses are never banned.
type AbuseSettings struct {
	Enabled       bool `json:"enabled"`
	WindowMinutes int  `json:"window_minutes"`
	RateLimited   int  `json:"rate_limited"`
	Blocked       int  `json:"blocked"`
	NotFound      int  `json:"not_found"`
}

// DefaultHoneypot is the spec's defaults, switched off until an admin
// turns it on.
var DefaultHoneypot = HoneypotSettings{
	Enabled: false, Response: "login", CatchallScore: 1, Threshold: 10, WindowHours: 24, BanDays: 7, MaxBanDays: 90,
	// High enough that a person on a site with a few broken links, or
	// behind a busy shared address, isn't caught; scanners and floods
	// pass these in seconds.
	Abuse: AbuseSettings{Enabled: true, WindowMinutes: 5, RateLimited: 30, Blocked: 50, NotFound: 100},
}

const settingHoneypot = "honeypot"

// Honeypot returns the honeypot settings.
func (s *Store) Honeypot(ctx context.Context) (HoneypotSettings, error) {
	v, err := s.GetSetting(ctx, settingHoneypot)
	if err != nil || v == "" {
		return DefaultHoneypot, err
	}
	h := DefaultHoneypot
	if err := json.Unmarshal([]byte(v), &h); err != nil {
		return DefaultHoneypot, nil //nolint:nilerr // fall back to defaults on bad data
	}
	return h, nil
}

// SaveHoneypot validates and stores honeypot settings.
func (s *Store) SaveHoneypot(ctx context.Context, h HoneypotSettings, by string) (HoneypotSettings, error) {
	errs := ValidationError{}
	switch h.Response {
	case "login", "server", "empty", "404":
	default:
		errs["response"] = "choose login, server, empty or 404"
	}
	if h.CatchallScore < 0 || h.CatchallScore > 100 {
		errs["catchall_score"] = "0 to 100"
	}
	if h.Threshold < 1 || h.Threshold > 10000 {
		errs["threshold"] = "1 to 10000"
	}
	if h.WindowHours < 1 || h.WindowHours > 24*7 {
		errs["window_hours"] = "1 to 168 hours"
	}
	if h.BanDays < 1 || h.BanDays > 365 {
		errs["ban_days"] = "1 to 365 days"
	}
	if h.MaxBanDays < h.BanDays || h.MaxBanDays > 3650 {
		errs["max_ban_days"] = "at least the first ban length, at most 3650 days"
	}
	a := h.Abuse
	if a.WindowMinutes < 1 || a.WindowMinutes > 60 {
		errs["abuse.window_minutes"] = "1 to 60 minutes"
	}
	for k, v := range map[string]int{"abuse.rate_limited": a.RateLimited, "abuse.blocked": a.Blocked, "abuse.not_found": a.NotFound} {
		if v < 0 || v > 100000 {
			errs[k] = "0 (off) to 100000"
		} else if v > 0 && v < 5 {
			errs[k] = "at least 5, so one slip doesn't ban someone (0 turns it off)"
		}
	}
	if a.Enabled && a.RateLimited == 0 && a.Blocked == 0 && a.NotFound == 0 {
		errs["abuse.enabled"] = "set at least one count, or turn abuse bans off"
	}
	if len(errs) > 0 {
		return h, errs
	}
	b, _ := json.Marshal(h)
	return h, s.SetSetting(ctx, settingHoneypot, string(b), by)
}

// TrapPath is a path scanners probe; requests to it on any host go to the
// honeypot.
type TrapPath struct {
	ID      int64  `json:"id"`
	Pattern string `json:"pattern"`
	Score   int    `json:"score"`
	Enabled bool   `json:"enabled"`
}

// Caddy path patterns: a leading slash, ordinary URL characters, and * as
// a wildcard. No placeholders or spaces.
var trapRE = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,199}$`)

// ListTrapPaths returns every trap path.
func (s *Store) ListTrapPaths(ctx context.Context) ([]TrapPath, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, pattern, score, enabled FROM trap_paths ORDER BY pattern`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []TrapPath{}
	for rows.Next() {
		var t TrapPath
		if err := rows.Scan(&t.ID, &t.Pattern, &t.Score, &t.Enabled); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveTrapPath creates (ID 0) or updates a trap path.
func (s *Store) SaveTrapPath(ctx context.Context, t TrapPath, by string) (TrapPath, error) {
	t.Pattern = strings.TrimSpace(t.Pattern)
	errs := ValidationError{}
	if !trapRE.MatchString(t.Pattern) {
		errs["pattern"] = "a path starting with /, using * as a wildcard (e.g. /.git/*)"
	}
	if t.Score < 0 || t.Score > 1000 {
		errs["score"] = "0 to 1000"
	}
	if len(errs) > 0 {
		return t, errs
	}
	var err error
	if t.ID == 0 {
		var res sql.Result
		res, err = s.db.ExecContext(ctx, `INSERT INTO trap_paths (pattern, score, enabled) VALUES (?, ?, ?)`, t.Pattern, t.Score, t.Enabled)
		if err == nil {
			t.ID, _ = res.LastInsertId()
		}
	} else {
		var res sql.Result
		res, err = s.db.ExecContext(ctx, `UPDATE trap_paths SET pattern = ?, score = ?, enabled = ? WHERE id = ?`, t.Pattern, t.Score, t.Enabled, t.ID)
		if err == nil {
			if n, _ := res.RowsAffected(); n == 0 {
				return t, ErrNotFound
			}
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return t, ValidationError{"pattern": "that path is already a trap"}
		}
		return t, err
	}
	return t, s.AuditEvent(ctx, by, "save", "trap_path", t.ID, t)
}

// DeleteTrapPath removes a trap path.
func (s *Store) DeleteTrapPath(ctx context.Context, id int64, by string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM trap_paths WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.AuditEvent(ctx, by, "delete", "trap_path", id, nil)
}

// Ban blocks an address or range on every host (spec F4 step 2).
type Ban struct {
	ID        int64      `json:"id"`
	CIDR      string     `json:"cidr"`
	Reason    string     `json:"reason"`
	Source    string     `json:"source"` // honeypot | manual | crowdsec
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	RemovedAt *time.Time `json:"removed_at,omitempty"`
	HitCount  int        `json:"hit_count"`
	Active    bool       `json:"active"`
}

func scanBans(rows *sql.Rows, now time.Time) ([]Ban, error) {
	defer func() { _ = rows.Close() }()
	out := []Ban{}
	for rows.Next() {
		var b Ban
		var exp, rem sql.NullTime
		if err := rows.Scan(&b.ID, &b.CIDR, &b.Reason, &b.Source, &b.CreatedBy, &b.CreatedAt, &exp, &rem, &b.HitCount); err != nil {
			return nil, err
		}
		if exp.Valid {
			b.ExpiresAt = &exp.Time
		}
		if rem.Valid {
			b.RemovedAt = &rem.Time
		}
		b.Active = !rem.Valid && (!exp.Valid || exp.Time.After(now))
		out = append(out, b)
	}
	return out, rows.Err()
}

const banCols = `id, cidr, reason, source, created_by, created_at, expires_at, removed_at, hit_count`

// ListBans returns bans, newest first; activeOnly limits to current ones.
func (s *Store) ListBans(ctx context.Context, activeOnly bool, limit int) ([]Ban, error) {
	now := time.Now().UTC()
	q := `SELECT ` + banCols + ` FROM bans`
	args := []any{}
	if activeOnly {
		q += ` WHERE removed_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`
		args = append(args, now)
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	return scanBans(rows, now)
}

// ActiveBanRanges returns the addresses currently banned, for the config.
func (s *Store) ActiveBanRanges(ctx context.Context) ([]string, error) {
	bans, err := s.ListBans(ctx, true, 100000)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []string{}
	for _, b := range bans {
		if !seen[b.CIDR] {
			seen[b.CIDR] = true
			out = append(out, b.CIDR)
		}
	}
	return out, nil
}

// ErrNeverBan is returned when banning an address on the never-block list.
var ErrNeverBan = ConflictError("That address is on the never-block list, so it can't be banned.")

// IsNeverBan reports whether ip is covered by the never-block list.
func (s *Store) IsNeverBan(ctx context.Context, ip string) (bool, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, nil //nolint:nilerr // a range, checked by prefix below
	}
	nb, err := s.ListNeverBan(ctx)
	if err != nil {
		return false, err
	}
	for _, n := range nb {
		if p, err := netip.ParsePrefix(n.CIDR); err == nil && p.Contains(addr) {
			return true, nil
		}
		if a, err := netip.ParseAddr(n.CIDR); err == nil && a == addr.Unmap() {
			return true, nil
		}
	}
	return false, nil
}

// AddBan bans an address or range. duration 0 means until removed.
func (s *Store) AddBan(ctx context.Context, cidr, reason, source string, duration time.Duration, hits int, by string) (Ban, error) {
	c, err := ParseRule(cidr)
	if err == nil && IsCountryRule(c) {
		err = errors.New("ban addresses or ranges, not countries")
	}
	if err != nil {
		return Ban{}, ValidationError{"cidr": err.Error()}
	}
	if never, err := s.IsNeverBan(ctx, c); err != nil {
		return Ban{}, err
	} else if never {
		return Ban{}, ErrNeverBan
	}
	var exp any
	if duration > 0 {
		exp = time.Now().UTC().Add(duration)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO bans (cidr, reason, source, created_by, expires_at, hit_count) VALUES (?, ?, ?, ?, ?, ?)`,
		c, reason, source, by, exp, hits)
	if err != nil {
		return Ban{}, err
	}
	id, _ := res.LastInsertId()
	if err := s.AuditEvent(ctx, by, "ban", "ban", id, map[string]any{"cidr": c, "reason": reason, "source": source, "for": duration.String()}); err != nil {
		return Ban{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+banCols+` FROM bans WHERE id = ?`, id)
	if err != nil {
		return Ban{}, err
	}
	bs, err := scanBans(rows, time.Now().UTC())
	if err != nil || len(bs) == 0 {
		return Ban{}, err
	}
	return bs[0], nil
}

// RemoveBan lifts a ban now.
func (s *Store) RemoveBan(ctx context.Context, id int64, by string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE bans SET removed_at = CURRENT_TIMESTAMP WHERE id = ? AND removed_at IS NULL`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.AuditEvent(ctx, by, "unban", "ban", id, nil)
}

// UnbanAddress lifts every active ban on exactly this address or range.
func (s *Store) UnbanAddress(ctx context.Context, cidr, by string) (int64, error) {
	c, err := ParseRule(cidr)
	if err != nil {
		return 0, ValidationError{"cidr": err.Error()}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE bans SET removed_at = CURRENT_TIMESTAMP
		WHERE cidr = ? AND removed_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, c, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_ = s.AuditEvent(ctx, by, "unban", "ban", 0, map[string]string{"cidr": c})
	}
	return n, nil
}

// PastBans counts earlier bans of an address (for doubling repeat bans).
func (s *Store) PastBans(ctx context.Context, cidr string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bans WHERE cidr = ? AND source IN ('honeypot', 'abuse')`, cidr).Scan(&n)
	return n, err
}

// IsBanned reports whether an exact address has an active ban.
func (s *Store) IsBanned(ctx context.Context, cidr string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bans WHERE cidr = ? AND removed_at IS NULL
		AND (expires_at IS NULL OR expires_at > ?)`, cidr, time.Now().UTC()).Scan(&n)
	return n > 0, err
}

// AddPoints records honeypot points for an address and returns its total
// within the window.
func (s *Store) AddPoints(ctx context.Context, ip string, at time.Time, points int, window time.Duration) (int, error) {
	if points > 0 {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO honeypot_points (ip, at, points) VALUES (?, ?, ?)`, ip, at.UTC(), points); err != nil {
			return 0, err
		}
	}
	var total sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT SUM(points) FROM honeypot_points WHERE ip = ? AND at > ?`,
		ip, at.UTC().Add(-window)).Scan(&total)
	return int(total.Int64), err
}

// ClearPoints forgets an address's points (after banning it).
func (s *Store) ClearPoints(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM honeypot_points WHERE ip = ?`, ip)
	return err
}

// PruneHoneypot deletes old points and ban records that ended more than
// keep ago (bans hold IPs; spec: 45 days after the ban ends).
func (s *Store) PruneHoneypot(ctx context.Context, now time.Time, pointsWindow, keep time.Duration) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM honeypot_points WHERE at < ?`, now.Add(-pointsWindow)); err != nil {
		return err
	}
	cut := now.Add(-keep)
	_, err := s.db.ExecContext(ctx, `DELETE FROM bans WHERE (removed_at IS NOT NULL AND removed_at < ?)
		OR (removed_at IS NULL AND expires_at IS NOT NULL AND expires_at < ?)`, cut, cut)
	return err
}

// HoneypotState is what the compiler needs for the honeypot.
type HoneypotState struct {
	Settings HoneypotSettings
	Traps    []TrapPath
	Bans     []string
}

// LoadHoneypotState reads honeypot settings, enabled traps and active bans.
func (s *Store) LoadHoneypotState(ctx context.Context) (HoneypotState, error) {
	var st HoneypotState
	var err error
	if st.Settings, err = s.Honeypot(ctx); err != nil {
		return st, err
	}
	traps, err := s.ListTrapPaths(ctx)
	if err != nil {
		return st, err
	}
	for _, t := range traps {
		if t.Enabled {
			st.Traps = append(st.Traps, t)
		}
	}
	if st.Bans, err = s.ActiveBanRanges(ctx); err != nil {
		return st, fmt.Errorf("loading bans: %w", err)
	}
	return st, nil
}
