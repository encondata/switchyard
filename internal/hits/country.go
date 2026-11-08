package hits

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CountryDetail is the breakdown of one country's traffic: how much, when,
// which hosts and paths it went to, from which IPs, and how it was answered.
type CountryDetail struct {
	Country string `json:"country"`
	Overview
	UniqueIPs int64    `json:"unique_ips"`
	Hosts     []TopRow `json:"hosts"`
	Paths     []TopRow `json:"paths"`
	IPs       []TopRow `json:"ips"`
	Status    []TopRow `json:"status"`
	Recent    []Hit    `json:"recent"`
}

// Country breaks down the traffic from one country ("" is unknown,
// LocalNetwork is private addresses). Totals, hosts and status come from
// the hourly rollups, like the dashboard's own numbers; IPs from the daily
// per-IP rollup; paths and recent requests from the raw log.
func (d *DB) Country(ctx context.Context, country string, from, to time.Time, hosts []string, limit int) (CountryDetail, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	c := CountryDetail{Country: country}
	var err error
	if c.Overview, err = d.overview(ctx, from, to, hosts, " AND country = ?", []any{country}); err != nil {
		return c, err
	}
	hf, hargs := hostFilter("host", hosts)
	hourFrom, dayFrom := from.Unix()/3600*3600, from.Unix()/86400*86400
	ms := func(t time.Time) int64 { return t.UnixMilli() }

	q := func(dst *[]TopRow, query string, args ...any) error {
		rows, err := d.db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		*dst = []TopRow{}
		for rows.Next() {
			var r TopRow
			var key any
			if err := rows.Scan(&key, &r.Count, &r.Blocked); err != nil {
				return err
			}
			r.Key = fmt.Sprint(key)
			*dst = append(*dst, r)
		}
		return rows.Err()
	}
	with := func(base []any) []any { return append(append(base, hargs...), limit) }

	//nolint:gosec // hf holds only "?" placeholders
	if err := q(&c.Hosts, `SELECT host, SUM(count), SUM(blocked) FROM hit_rollup
		WHERE country = ? AND hour >= ? AND hour < ?`+hf+` GROUP BY host ORDER BY 2 DESC LIMIT ?`,
		with([]any{country, hourFrom, to.Unix()})...); err != nil {
		return c, err
	}
	//nolint:gosec // hf holds only "?" placeholders
	if err := q(&c.Status, `SELECT status_class, SUM(count), SUM(blocked) FROM hit_rollup
		WHERE country = ? AND hour >= ? AND hour < ?`+hf+` GROUP BY status_class ORDER BY 2 DESC LIMIT ?`,
		with([]any{country, hourFrom, to.Unix()})...); err != nil {
		return c, err
	}
	for i := range c.Status {
		if c.Status[i].Key == "0" {
			c.Status[i].Key = "no response"
		} else {
			c.Status[i].Key += "xx"
		}
	}
	//nolint:gosec // hf holds only "?" placeholders
	if err := q(&c.IPs, `SELECT ip, SUM(count), SUM(blocked) FROM ip_daily
		WHERE country = ? AND day >= ? AND day < ?`+hf+` GROUP BY ip ORDER BY 2 DESC LIMIT ?`,
		with([]any{country, dayFrom, to.Unix()})...); err != nil {
		return c, err
	}
	//nolint:gosec // hf holds only "?" placeholders
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT ip) FROM ip_daily
		WHERE country = ? AND day >= ? AND day < ?`+hf, append([]any{country, dayFrom, to.Unix()}, hargs...)...).
		Scan(&c.UniqueIPs); err != nil && err != sql.ErrNoRows {
		return c, err
	}
	//nolint:gosec // hf holds only "?" placeholders
	if err := q(&c.Paths, `SELECT path, COUNT(*), SUM(CASE WHEN matched = 'allowed' THEN 0 ELSE 1 END) FROM hits
		WHERE country = ? AND ts >= ? AND ts < ?`+hf+` GROUP BY path ORDER BY 2 DESC LIMIT ?`,
		with([]any{country, ms(from), ms(to)})...); err != nil {
		return c, err
	}
	//nolint:gosec // hf holds only "?" placeholders
	c.Recent, err = d.queryHits(ctx, `SELECT `+hitCols+` FROM hits WHERE country = ? AND ts >= ? AND ts < ?`+hf+
		` ORDER BY ts DESC LIMIT 25`, append([]any{country, ms(from), ms(to)}, hargs...)...)
	if c.Recent == nil {
		c.Recent = []Hit{}
	}
	return c, err
}
