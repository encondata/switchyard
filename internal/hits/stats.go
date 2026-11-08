package hits

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Point is one bucket of the traffic chart.
type Point struct {
	T        time.Time `json:"t"`
	Requests int64     `json:"requests"`
	Bytes    int64     `json:"bytes"`
	Errors   int64     `json:"errors"` // 5xx
	Blocked  int64     `json:"blocked"`
}

// Overview is the dashboard's headline numbers and chart.
type Overview struct {
	Series   []Point `json:"series"`
	Requests int64   `json:"requests"`
	Bytes    int64   `json:"bytes"`
	Errors   int64   `json:"errors"`
	Blocked  int64   `json:"blocked"`
	// Bucket is the chart's step in seconds (3600 or 86400).
	Bucket int64 `json:"bucket"`
}

// Overview sums the hourly rollups (no raw rows), so it stays fast over
// long ranges. hosts == nil means every host.
func (d *DB) Overview(ctx context.Context, from, to time.Time, hosts []string) (Overview, error) {
	return d.overview(ctx, from, to, hosts, "", nil)
}

// overview is Overview with an extra filter on the rollups (" AND ...").
func (d *DB) overview(ctx context.Context, from, to time.Time, hosts []string, extra string, extraArgs []any) (Overview, error) {
	bucket := int64(3600)
	if to.Sub(from) > 72*time.Hour {
		bucket = 86400
	}
	hf, args := hostFilter("host", hosts)
	//nolint:gosec // bucket is a constant and hf holds only "?" placeholders
	q := fmt.Sprintf(`SELECT (hour / %d) * %d AS b, SUM(count), SUM(bytes),
		SUM(CASE WHEN status_class = 5 THEN count ELSE 0 END), SUM(blocked)
		FROM hit_rollup WHERE hour >= ? AND hour < ?%s%s GROUP BY b ORDER BY b`, bucket, bucket, extra, hf)
	qargs := append(append([]any{from.Unix() / 3600 * 3600, to.Unix()}, extraArgs...), args...)
	rows, err := d.db.QueryContext(ctx, q, qargs...) //nolint:gosec // q is built from constants and "?" placeholders
	if err != nil {
		return Overview{}, err
	}
	defer func() { _ = rows.Close() }()
	byT := map[int64]Point{}
	o := Overview{Bucket: bucket}
	for rows.Next() {
		var b int64
		var p Point
		if err := rows.Scan(&b, &p.Requests, &p.Bytes, &p.Errors, &p.Blocked); err != nil {
			return o, err
		}
		p.T = time.Unix(b, 0).UTC()
		byT[b] = p
		o.Requests += p.Requests
		o.Bytes += p.Bytes
		o.Errors += p.Errors
		o.Blocked += p.Blocked
	}
	// Fill gaps with zeros so the chart's time axis is even.
	for b := from.Unix() / bucket * bucket; b < to.Unix(); b += bucket {
		p, ok := byT[b]
		if !ok {
			p = Point{T: time.Unix(b, 0).UTC()}
		}
		o.Series = append(o.Series, p)
	}
	return o, rows.Err()
}

// TopRow is one entry of a "top" list.
type TopRow struct {
	Key     string `json:"key"`
	Count   int64  `json:"count"`
	Blocked int64  `json:"blocked"`
	Country string `json:"country,omitempty"`
}

// Top dimensions.
const (
	DimIP      = "ip"
	DimPath    = "path"
	DimCountry = "country"
	DimStatus  = "status"
	DimHost    = "host"
)

// Top returns the busiest IPs, paths, countries, status classes or hosts.
func (d *DB) Top(ctx context.Context, dim string, from, to time.Time, hosts []string, limit int) ([]TopRow, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	hf, hargs := hostFilter("host", hosts)
	var q string
	var args []any
	dayFrom, dayTo := from.Unix()/86400*86400, to.Unix()
	switch dim {
	case DimIP:
		q = `SELECT ip, SUM(count), SUM(blocked), MAX(country) FROM ip_daily WHERE day >= ? AND day < ?` + hf +
			` GROUP BY ip ORDER BY 2 DESC LIMIT ?`
		args = []any{dayFrom, dayTo}
	case DimPath:
		q = `SELECT path, SUM(count), 0, '' FROM path_daily WHERE day >= ? AND day < ?` + hf +
			` GROUP BY path ORDER BY 2 DESC LIMIT ?`
		args = []any{dayFrom, dayTo}
	case DimCountry, DimStatus, DimHost:
		col := map[string]string{DimCountry: "country", DimStatus: "status_class", DimHost: "host"}[dim]
		q = `SELECT ` + col + `, SUM(count), SUM(blocked), '' FROM hit_rollup WHERE hour >= ? AND hour < ?` + hf +
			` GROUP BY ` + col + ` ORDER BY 2 DESC LIMIT ?`
		args = []any{from.Unix() / 3600 * 3600, to.Unix()}
	default:
		return nil, fmt.Errorf("unknown dimension %q", dim)
	}
	args = append(append(args, hargs...), limit)
	rows, err := d.db.QueryContext(ctx, q, args...) //nolint:gosec // q is built from constants
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []TopRow{}
	for rows.Next() {
		var r TopRow
		var key any
		if err := rows.Scan(&key, &r.Count, &r.Blocked, &r.Country); err != nil {
			return nil, err
		}
		r.Key = fmt.Sprint(key)
		if dim == DimStatus {
			if r.Key == "0" {
				r.Key = "no response"
			} else {
				r.Key += "xx"
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Latency is p50/p95 response time over a sample of recent requests.
type Latency struct {
	P50     float64 `json:"p50_ms"`
	P95     float64 `json:"p95_ms"`
	Samples int     `json:"samples"`
}

// Latency samples the most recent 20,000 allowed requests in the range.
func (d *DB) Latency(ctx context.Context, from, to time.Time, hosts []string) (Latency, error) {
	hf, args := hostFilter("host", hosts)
	//nolint:gosec // hf holds only "?" placeholders from hostFilter
	rows, err := d.db.QueryContext(ctx, `SELECT duration_ms FROM hits WHERE ts >= ? AND ts < ? AND matched = 'allowed'`+hf+
		` ORDER BY ts DESC LIMIT 20000`, append([]any{from.UnixMilli(), to.UnixMilli()}, args...)...)
	if err != nil {
		return Latency{}, err
	}
	defer func() { _ = rows.Close() }()
	var v []float64
	for rows.Next() {
		var x float64
		if err := rows.Scan(&x); err != nil {
			return Latency{}, err
		}
		v = append(v, x)
	}
	if len(v) == 0 {
		return Latency{}, rows.Err()
	}
	sort.Float64s(v)
	pct := func(p float64) float64 { return v[int(p*float64(len(v)-1))] }
	return Latency{P50: pct(0.5), P95: pct(0.95), Samples: len(v)}, rows.Err()
}

const hitCols = `id, ts, host, client_ip, country, method, path, status, bytes, duration_ms, user_agent, matched, reason`

func (d *DB) queryHits(ctx context.Context, q string, args ...any) ([]Hit, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Hit{}
	for rows.Next() {
		var h Hit
		var ts int64
		if err := rows.Scan(&h.ID, &ts, &h.Host, &h.ClientIP, &h.Country, &h.Method, &h.Path, &h.Status, &h.Bytes,
			&h.DurationMS, &h.UserAgent, &h.Matched, &h.Reason); err != nil {
			return nil, err
		}
		h.TS = time.UnixMilli(ts).UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}

// Tail returns hits newer than afterID (newest last), at most limit; with
// many new hits it returns the latest ones (a sample of the live stream).
func (d *DB) Tail(ctx context.Context, afterID int64, hosts []string, limit int) ([]Hit, error) {
	hf, args := hostFilter("host", hosts)
	//nolint:gosec // hf holds only "?" placeholders from hostFilter
	hs, err := d.queryHits(ctx, `SELECT `+hitCols+` FROM hits WHERE id > ?`+hf+` ORDER BY id DESC LIMIT ?`,
		append(append([]any{afterID}, args...), limit)...)
	for i, j := 0, len(hs)-1; i < j; i, j = i+1, j-1 {
		hs[i], hs[j] = hs[j], hs[i]
	}
	return hs, err
}

// IPHistory is everything recent about one address.
type IPHistory struct {
	IP      string   `json:"ip"`
	Country string   `json:"country"`
	Total   int64    `json:"total"`
	Blocked int64    `json:"blocked"`
	Hosts   []TopRow `json:"hosts"`
	Recent  []Hit    `json:"recent"`
}

// IP returns an address's recent requests and per-host counts.
func (d *DB) IP(ctx context.Context, ip string, from time.Time) (IPHistory, error) {
	h := IPHistory{IP: ip, Hosts: []TopRow{}}
	rows, err := d.db.QueryContext(ctx, `SELECT host, SUM(count), SUM(blocked), MAX(country) FROM ip_daily
		WHERE ip = ? AND day >= ? GROUP BY host ORDER BY 2 DESC`, ip, from.Unix()/86400*86400)
	if err != nil {
		return h, err
	}
	for rows.Next() {
		var r TopRow
		if err := rows.Scan(&r.Key, &r.Count, &r.Blocked, &r.Country); err != nil {
			_ = rows.Close()
			return h, err
		}
		h.Hosts = append(h.Hosts, r)
		h.Total += r.Count
		h.Blocked += r.Blocked
		if h.Country == "" {
			h.Country = r.Country
		}
	}
	_ = rows.Close()
	h.Recent, err = d.queryHits(ctx, `SELECT `+hitCols+` FROM hits WHERE client_ip = ? ORDER BY ts DESC LIMIT 200`, ip)
	return h, err
}

// HoneypotTop lists the most common paths, sources (ip) or user agents (ua)
// among honeypot hits.
func (d *DB) HoneypotTop(ctx context.Context, dim string, from, to time.Time, limit int) ([]TopRow, error) {
	col := map[string]string{"path": "path", "ip": "client_ip", "ua": "user_agent", "host": "host"}[dim]
	if col == "" {
		return nil, fmt.Errorf("unknown dimension %q", dim)
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	//nolint:gosec // col comes from the fixed map above
	rows, err := d.db.QueryContext(ctx, `SELECT `+col+`, COUNT(*), MAX(country) FROM hits
		WHERE matched = 'honeypot' AND ts >= ? AND ts < ? GROUP BY `+col+` ORDER BY 2 DESC LIMIT ?`,
		from.UnixMilli(), to.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []TopRow{}
	for rows.Next() {
		var r TopRow
		if err := rows.Scan(&r.Key, &r.Count, &r.Country); err != nil {
			return nil, err
		}
		if dim != "ip" {
			r.Country = ""
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// HoneypotRecent returns the latest honeypot hits.
func (d *DB) HoneypotRecent(ctx context.Context, limit int) ([]Hit, error) {
	return d.queryHits(ctx, `SELECT `+hitCols+` FROM hits WHERE matched = 'honeypot' ORDER BY id DESC LIMIT ?`, limit)
}
