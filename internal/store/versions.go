package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ConfigVersion is one attempt to apply a Caddy config (spec §2, CPM-9).
type ConfigVersion struct {
	N         int64     `json:"n"`
	JSON      string    `json:"json,omitempty"`
	SHA256    string    `json:"sha256"`
	AppliedBy string    `json:"applied_by"`
	AppliedAt time.Time `json:"applied_at"`
	Result    string    `json:"result"` // ok | failed
	Error     string    `json:"error,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// AddConfigVersion records an apply attempt and returns its number.
func (s *Store) AddConfigVersion(ctx context.Context, v ConfigVersion) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO config_versions (json, sha256, applied_by, result, error, note)
		VALUES (?, ?, ?, ?, ?, ?)`, v.JSON, v.SHA256, v.AppliedBy, v.Result, v.Error, v.Note)
	if err != nil {
		return 0, err
	}
	n, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	action := "apply"
	if v.Result != "ok" {
		action = "apply_failed"
	}
	if err := audit(ctx, tx, v.AppliedBy, action, "config", n, nil, map[string]string{"note": v.Note, "error": v.Error}); err != nil {
		return 0, err
	}
	return n, tx.Commit()
}

// ListConfigVersions returns the newest versions first, without their JSON.
func (s *Store) ListConfigVersions(ctx context.Context, limit int) ([]ConfigVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT n, sha256, applied_by, applied_at, result, error, note
		FROM config_versions ORDER BY n DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []ConfigVersion{}
	for rows.Next() {
		var v ConfigVersion
		if err := rows.Scan(&v.N, &v.SHA256, &v.AppliedBy, &v.AppliedAt, &v.Result, &v.Error, &v.Note); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetConfigVersion returns one version including its JSON.
func (s *Store) GetConfigVersion(ctx context.Context, n int64) (ConfigVersion, error) {
	var v ConfigVersion
	err := s.db.QueryRowContext(ctx, `SELECT n, json, sha256, applied_by, applied_at, result, error, note
		FROM config_versions WHERE n = ?`, n).
		Scan(&v.N, &v.JSON, &v.SHA256, &v.AppliedBy, &v.AppliedAt, &v.Result, &v.Error, &v.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}

// LastAppliedConfig returns the newest successfully applied version.
func (s *Store) LastAppliedConfig(ctx context.Context) (ConfigVersion, error) {
	var v ConfigVersion
	err := s.db.QueryRowContext(ctx, `SELECT n, json, sha256, applied_by, applied_at, result, error, note
		FROM config_versions WHERE result = 'ok' ORDER BY n DESC LIMIT 1`).
		Scan(&v.N, &v.JSON, &v.SHA256, &v.AppliedBy, &v.AppliedAt, &v.Result, &v.Error, &v.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}

// PreviousAppliedConfig returns the newest successful version before n.
func (s *Store) PreviousAppliedConfig(ctx context.Context, n int64) (ConfigVersion, error) {
	var v ConfigVersion
	err := s.db.QueryRowContext(ctx, `SELECT n, json, sha256, applied_by, applied_at, result, error, note
		FROM config_versions WHERE result = 'ok' AND n < ? ORDER BY n DESC LIMIT 1`, n).
		Scan(&v.N, &v.JSON, &v.SHA256, &v.AppliedBy, &v.AppliedAt, &v.Result, &v.Error, &v.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}
