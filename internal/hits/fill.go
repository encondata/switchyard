package hits

import (
	"context"
	"database/sql"
)

// FillCountries fills in the country of stored requests that were logged
// without one (before a country database was installed). locate gives the
// country for an IP, or "" if still unknown.
//
// The raw rows get the country, and their counts move from the "unknown"
// rows of the hourly and per-IP rollups to the right country, so the
// dashboard's totals stay the same and the countries appear for the past
// as well. It returns how many requests were filled in.
func (d *DB) FillCountries(ctx context.Context, locate func(ip string) string) (int64, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT DISTINCT client_ip FROM hits WHERE country = ''`)
	if err != nil {
		return 0, err
	}
	found := map[string]string{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			_ = rows.Close()
			return 0, err
		}
		if c := locate(ip); c != "" {
			found[ip] = c
		}
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil || len(found) == 0 {
		return 0, err
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var filled int64
	for ip, country := range found {
		n, err := moveCountry(ctx, tx, ip, country)
		if err != nil {
			return 0, err
		}
		filled += n
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM hit_rollup WHERE country = '' AND count <= 0`); err != nil {
		return 0, err
	}
	return filled, tx.Commit()
}

// moveCountry gives one IP's unknown-country requests their country.
func moveCountry(ctx context.Context, tx *sql.Tx, ip, country string) (int64, error) {
	// Each hour/host/status class these requests were counted under.
	rows, err := tx.QueryContext(ctx, `SELECT (ts / 1000) / 3600 * 3600, host, status / 100,
		COUNT(*), COALESCE(SUM(bytes), 0), SUM(CASE WHEN matched = 'allowed' THEN 0 ELSE 1 END)
		FROM hits WHERE client_ip = ? AND country = '' GROUP BY 1, 2, 3`, ip)
	if err != nil {
		return 0, err
	}
	type group struct {
		hour                  int64
		host                  string
		class                 int
		count, bytes, blocked int64
	}
	var groups []group
	for rows.Next() {
		var g group
		if err := rows.Scan(&g.hour, &g.host, &g.class, &g.count, &g.bytes, &g.blocked); err != nil {
			_ = rows.Close()
			return 0, err
		}
		groups = append(groups, g)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	var n int64
	for _, g := range groups {
		if _, err := tx.ExecContext(ctx, `UPDATE hit_rollup SET count = count - ?, bytes = bytes - ?, blocked = blocked - ?
			WHERE hour = ? AND host = ? AND country = '' AND status_class = ?`,
			g.count, g.bytes, g.blocked, g.hour, g.host, g.class); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO hit_rollup (hour, host, country, status_class, count, bytes, blocked)
			VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (hour, host, country, status_class) DO UPDATE SET
			count = count + excluded.count, bytes = bytes + excluded.bytes, blocked = blocked + excluded.blocked`,
			g.hour, g.host, country, g.class, g.count, g.bytes, g.blocked); err != nil {
			return 0, err
		}
		n += g.count
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hits SET country = ? WHERE client_ip = ? AND country = ''`, country, ip); err != nil {
		return 0, err
	}
	// The per-IP daily rollup carries the country by IP, so it can be set
	// even for days whose raw requests have been pruned.
	if _, err := tx.ExecContext(ctx, `UPDATE ip_daily SET country = ? WHERE ip = ? AND country = ''`, country, ip); err != nil {
		return 0, err
	}
	return n, nil
}
