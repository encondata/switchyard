package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Alert kinds.
const (
	AlertCaddyUnreachable = "caddy_unreachable"
	AlertDrift            = "drift"
	AlertApplyFailed      = "apply_failed"
	AlertCertExpiring     = "cert_expiring"
	AlertCertFailed       = "cert_failed"
)

// Alert is something an admin should look at.
type Alert struct {
	ID         int64      `json:"id"`
	Kind       string     `json:"kind"`
	Subject    string     `json:"subject"`
	Message    string     `json:"message"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// RaiseAlert opens an alert, or refreshes the open one for the same kind
// and subject. It reports whether the alert is new.
func (s *Store) RaiseAlert(ctx context.Context, kind, subject, message string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE alerts SET message = ?, last_seen_at = CURRENT_TIMESTAMP
		WHERE kind = ? AND subject = ? AND resolved_at IS NULL`, message, kind, subject)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return false, nil
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO alerts (kind, subject, message) VALUES (?, ?, ?)`, kind, subject, message)
	return err == nil, err
}

// ResolveAlert closes the open alert for a kind and subject, if any.
func (s *Store) ResolveAlert(ctx context.Context, kind, subject string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET resolved_at = CURRENT_TIMESTAMP
		WHERE kind = ? AND subject = ? AND resolved_at IS NULL`, kind, subject)
	return err
}

// ResolveAlertsExcept closes open alerts of a kind whose subject isn't in keep.
func (s *Store) ResolveAlertsExcept(ctx context.Context, kind string, keep map[string]bool) error {
	open, err := s.ListAlerts(ctx, true, 1000)
	if err != nil {
		return err
	}
	for _, a := range open {
		if a.Kind == kind && !keep[a.Subject] {
			if err := s.ResolveAlert(ctx, kind, a.Subject); err != nil {
				return err
			}
		}
	}
	return nil
}

// ListAlerts returns open alerts (openOnly) or the most recent ones.
func (s *Store) ListAlerts(ctx context.Context, openOnly bool, limit int) ([]Alert, error) {
	q := `SELECT id, kind, subject, message, created_at, last_seen_at, resolved_at FROM alerts`
	if openOnly {
		q += ` WHERE resolved_at IS NULL`
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var resolved sql.NullTime
		if err := rows.Scan(&a.ID, &a.Kind, &a.Subject, &a.Message, &a.CreatedAt, &a.LastSeenAt, &resolved); err != nil {
			return nil, err
		}
		if resolved.Valid {
			a.ResolvedAt = &resolved.Time
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// LatestConfigVersion returns the newest apply attempt, successful or not.
func (s *Store) LatestConfigVersion(ctx context.Context) (ConfigVersion, error) {
	var v ConfigVersion
	err := s.db.QueryRowContext(ctx, `SELECT n, sha256, applied_by, applied_at, result, error, note
		FROM config_versions ORDER BY n DESC LIMIT 1`).
		Scan(&v.N, &v.SHA256, &v.AppliedBy, &v.AppliedAt, &v.Result, &v.Error, &v.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	return v, err
}
