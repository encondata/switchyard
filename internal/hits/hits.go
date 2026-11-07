// Package hits stores and queries traffic from Caddy's access logs (spec
// F5, CPM-22/23). It uses its own SQLite file so the config database (and
// its backups) stay small.
//
// Tables:
//   - hits: one row per request, kept RetainHits (45 days by default)
//   - hit_rollup: per hour × host × country × status class; no IPs; kept
//     13 months
//   - ip_daily, path_daily: per day × host, for fast "top" lists; IP rows
//     are kept as long as raw hits
package hits

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	// Pure-Go SQLite.
	_ "modernc.org/sqlite"
)

// Hit is one request.
type Hit struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	Host       string    `json:"host"`
	ClientIP   string    `json:"client_ip"`
	Country    string    `json:"country"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	Bytes      int64     `json:"bytes"`
	DurationMS float64   `json:"duration_ms"`
	UserAgent  string    `json:"user_agent"`
	Matched    string    `json:"matched"` // allowed | blocked | honeypot
	Reason     string    `json:"reason"`
}

// Retention defaults (spec F5, decided 07 Nov 2026).
const (
	DefaultRetainHits    = 45 * 24 * time.Hour
	DefaultRetainRollups = 395 * 24 * time.Hour // ~13 months
)

// DB is the hits database.
type DB struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS hits (
	id          INTEGER PRIMARY KEY,
	ts          INTEGER NOT NULL, -- unix milliseconds
	host        TEXT NOT NULL,
	client_ip   TEXT NOT NULL,
	country     TEXT NOT NULL DEFAULT '',
	method      TEXT NOT NULL,
	path        TEXT NOT NULL,
	status      INTEGER NOT NULL,
	bytes       INTEGER NOT NULL,
	duration_ms REAL NOT NULL,
	user_agent  TEXT NOT NULL DEFAULT '',
	matched     TEXT NOT NULL,
	reason      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS hits_ts ON hits (ts);
CREATE INDEX IF NOT EXISTS hits_host_ts ON hits (host, ts);
CREATE INDEX IF NOT EXISTS hits_ip_ts ON hits (client_ip, ts);

CREATE TABLE IF NOT EXISTS hit_rollup (
	hour         INTEGER NOT NULL, -- unix seconds, start of the hour
	host         TEXT NOT NULL,
	country      TEXT NOT NULL,
	status_class INTEGER NOT NULL, -- 2, 3, 4, 5 (0 = no response)
	count        INTEGER NOT NULL,
	bytes        INTEGER NOT NULL,
	blocked      INTEGER NOT NULL,
	PRIMARY KEY (hour, host, country, status_class)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS ip_daily (
	day     INTEGER NOT NULL, -- unix seconds, start of the UTC day
	host    TEXT NOT NULL,
	ip      TEXT NOT NULL,
	country TEXT NOT NULL,
	count   INTEGER NOT NULL,
	blocked INTEGER NOT NULL,
	PRIMARY KEY (day, host, ip)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS path_daily (
	day   INTEGER NOT NULL,
	host  TEXT NOT NULL,
	path  TEXT NOT NULL,
	count INTEGER NOT NULL,
	PRIMARY KEY (day, host, path)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS ingest_state (
	file   TEXT PRIMARY KEY,
	ident  TEXT NOT NULL,
	offset INTEGER NOT NULL
);
`

// Open opens (creating if needed) the hits database.
func Open(ctx context.Context, path string) (*DB, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("hits: schema: %w", err)
	}
	return &DB{db: db}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// MaxPathLen truncates long paths (scanners send very long ones).
const MaxPathLen = 300

// Insert stores hits and updates the rollups, in one transaction.
func (d *DB) Insert(ctx context.Context, batch []Hit) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	ins, err := tx.PrepareContext(ctx, `INSERT INTO hits (ts, host, client_ip, country, method, path, status, bytes,
		duration_ms, user_agent, matched, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = ins.Close() }()

	type rk struct {
		hour    int64
		host    string
		country string
		class   int
	}
	type rv struct{ count, bytes, blocked int64 }
	type ik struct {
		day      int64
		host, ip string
		country  string
	}
	type pk struct {
		day        int64
		host, path string
	}
	rollup := map[rk]*rv{}
	ips := map[ik]*rv{}
	paths := map[pk]int64{}
	for _, h := range batch {
		if len(h.Path) > MaxPathLen {
			h.Path = h.Path[:MaxPathLen]
		}
		if _, err := ins.ExecContext(ctx, h.TS.UnixMilli(), h.Host, h.ClientIP, h.Country, h.Method, h.Path, h.Status,
			h.Bytes, h.DurationMS, h.UserAgent, h.Matched, h.Reason); err != nil {
			return err
		}
		blocked := int64(0)
		if h.Matched != "allowed" {
			blocked = 1
		}
		k := rk{h.TS.Unix() / 3600 * 3600, h.Host, h.Country, h.Status / 100}
		if rollup[k] == nil {
			rollup[k] = &rv{}
		}
		rollup[k].count++
		rollup[k].bytes += h.Bytes
		rollup[k].blocked += blocked
		day := h.TS.Unix() / 86400 * 86400
		ikey := ik{day, h.Host, h.ClientIP, h.Country}
		if ips[ikey] == nil {
			ips[ikey] = &rv{}
		}
		ips[ikey].count++
		ips[ikey].blocked += blocked
		paths[pk{day, h.Host, h.Path}]++
	}
	for k, v := range rollup {
		if _, err := tx.ExecContext(ctx, `INSERT INTO hit_rollup (hour, host, country, status_class, count, bytes, blocked)
			VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (hour, host, country, status_class) DO UPDATE SET
			count = count + excluded.count, bytes = bytes + excluded.bytes, blocked = blocked + excluded.blocked`,
			k.hour, k.host, k.country, k.class, v.count, v.bytes, v.blocked); err != nil {
			return err
		}
	}
	for k, v := range ips {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ip_daily (day, host, ip, country, count, blocked) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (day, host, ip) DO UPDATE SET count = count + excluded.count, blocked = blocked + excluded.blocked`,
			k.day, k.host, k.ip, k.country, v.count, v.blocked); err != nil {
			return err
		}
	}
	for k, n := range paths {
		if _, err := tx.ExecContext(ctx, `INSERT INTO path_daily (day, host, path, count) VALUES (?, ?, ?, ?)
			ON CONFLICT (day, host, path) DO UPDATE SET count = count + excluded.count`, k.day, k.host, k.path, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Prune deletes data past retention, in batches so the ingester isn't
// blocked for long. It returns how many raw hits it deleted.
func (d *DB) Prune(ctx context.Context, now time.Time, retainHits, retainRollups time.Duration) (int64, error) {
	hitCut := now.Add(-retainHits)
	var total int64
	for {
		res, err := d.db.ExecContext(ctx, `DELETE FROM hits WHERE id IN (SELECT id FROM hits WHERE ts < ? LIMIT 10000)`, hitCut.UnixMilli())
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < 10000 {
			break
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	day := hitCut.Unix() / 86400 * 86400
	for _, q := range []string{`DELETE FROM ip_daily WHERE day < ?`, `DELETE FROM path_daily WHERE day < ?`} {
		if _, err := d.db.ExecContext(ctx, q, day); err != nil {
			return total, err
		}
	}
	_, err := d.db.ExecContext(ctx, `DELETE FROM hit_rollup WHERE hour < ?`, now.Add(-retainRollups).Unix())
	return total, err
}

// Offset returns where the ingester left off in a file.
func (d *DB) Offset(ctx context.Context, file string) (ident string, offset int64, err error) {
	err = d.db.QueryRowContext(ctx, `SELECT ident, offset FROM ingest_state WHERE file = ?`, file).Scan(&ident, &offset)
	if err == sql.ErrNoRows {
		return "", 0, nil
	}
	return ident, offset, err
}

// SaveOffset records the ingester's position.
func (d *DB) SaveOffset(ctx context.Context, file, ident string, offset int64) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO ingest_state (file, ident, offset) VALUES (?, ?, ?)
		ON CONFLICT (file) DO UPDATE SET ident = excluded.ident, offset = excluded.offset`, file, ident, offset)
	return err
}

// hostFilter builds "AND host IN (...)" for a host list (nil = all hosts).
func hostFilter(col string, hosts []string) (string, []any) {
	if hosts == nil {
		return "", nil
	}
	if len(hosts) == 0 {
		return " AND 0", nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(hosts)), ",")
	args := make([]any, len(hosts))
	for i, h := range hosts {
		args[i] = h
	}
	return " AND " + col + " IN (" + ph + ")", args
}
