// Package monitor checks, in the background, that Caddy is reachable and
// running CPM's config (drift, CPM-10), and that certificates are healthy
// (CPM-14, CPM-24). Problems become in-app alerts through a Notifier, so
// email can be added later without touching the checks.
package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/encondata/switchyard/internal/apply"
	"github.com/encondata/switchyard/internal/certs"
	"github.com/encondata/switchyard/internal/store"
)

// Notifier is told about new alerts. In-app alerts are stored by the
// monitor itself; a notifier adds other channels (email later).
type Notifier interface {
	Notify(ctx context.Context, a store.Alert)
}

// LogNotifier writes new alerts to the server log.
type LogNotifier struct{ Log *slog.Logger }

// Notify implements Notifier.
func (n LogNotifier) Notify(_ context.Context, a store.Alert) {
	n.Log.Warn("alert", "kind", a.Kind, "subject", a.Subject, "message", a.Message)
}

// Caddy is the part of the admin API the monitor reads.
type Caddy interface {
	Config(ctx context.Context) ([]byte, error)
}

// CertError is the last certificate failure Caddy logged for a name.
type CertError struct {
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// CertRow is one domain on the certificates page.
type CertRow struct {
	Domain    string     `json:"domain"`
	HostID    int64      `json:"host_id"`
	TLSMode   string     `json:"tls_mode"`
	State     string     `json:"state"`
	Issuer    string     `json:"issuer,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	LastError *CertError `json:"last_error,omitempty"`
}

// Snapshot is the result of the last check, for the health page.
type Snapshot struct {
	CheckedAt      time.Time            `json:"checked_at"`
	CaddyReachable bool                 `json:"caddy_reachable"`
	CaddyError     string               `json:"caddy_error,omitempty"`
	Drift          bool                 `json:"drift"`
	LastApply      *store.ConfigVersion `json:"last_apply,omitempty"`
	LogBytes       int64                `json:"log_bytes"`
}

// Monitor runs the checks.
type Monitor struct {
	Store        *store.Store
	Caddy        Caddy
	CaddyDataDir string
	// TLSLogFile is Caddy's certificate log (compiler.Settings.TLSLogFile)
	// as seen by CPM; LogDir is the folder whose size the health page shows.
	TLSLogFile string
	LogDir     string
	Notifier   Notifier
	Interval   time.Duration
	Log        *slog.Logger

	mu        sync.Mutex
	snap      Snapshot
	certErrs  map[string]CertError
	logOffset int64
}

// Run checks every Interval until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	interval := m.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := m.Check(ctx); err != nil && ctx.Err() == nil {
			m.Log.Warn("monitor check failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Snapshot returns the last check's result.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snap
}

func (m *Monitor) raise(ctx context.Context, kind, subject, msg string) error {
	isNew, err := m.Store.RaiseAlert(ctx, kind, subject, msg)
	if err == nil && isNew && m.Notifier != nil {
		m.Notifier.Notify(ctx, store.Alert{Kind: kind, Subject: subject, Message: msg, CreatedAt: time.Now()})
	}
	return err
}

// Check runs every check once.
func (m *Monitor) Check(ctx context.Context) error {
	snap := Snapshot{CheckedAt: time.Now().UTC()}
	var errs []error

	// Last apply result.
	if v, err := m.Store.LatestConfigVersion(ctx); err == nil {
		snap.LastApply = &v
		if v.Result == "failed" {
			errs = append(errs, m.raise(ctx, store.AlertApplyFailed, "config",
				fmt.Sprintf("Applying version %d failed: %s", v.N, v.Error)))
		} else {
			errs = append(errs, m.Store.ResolveAlert(ctx, store.AlertApplyFailed, "config"))
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		errs = append(errs, err)
	}

	// Caddy reachable, and running what CPM applied last.
	running, err := m.Caddy.Config(ctx)
	if err != nil {
		snap.CaddyError = err.Error()
		errs = append(errs, m.raise(ctx, store.AlertCaddyUnreachable, "caddy", "CPM can't reach Caddy's admin API: "+err.Error()))
	} else {
		snap.CaddyReachable = true
		errs = append(errs, m.Store.ResolveAlert(ctx, store.AlertCaddyUnreachable, "caddy"))
		if last, lerr := m.Store.LastAppliedConfig(ctx); lerr == nil {
			snap.Drift = !apply.SameIgnoringBans(running, []byte(last.JSON))
			if snap.Drift {
				errs = append(errs, m.raise(ctx, store.AlertDrift, "caddy",
					"Caddy is running a config CPM didn't apply. Review & apply to put CPM's config back."))
			} else {
				errs = append(errs, m.Store.ResolveAlert(ctx, store.AlertDrift, "caddy"))
			}
		}
	}

	// Certificates.
	m.readTLSLog()
	rows, err := m.Certs(ctx)
	if err != nil {
		errs = append(errs, err)
	} else {
		expiring, failed := map[string]bool{}, map[string]bool{}
		for _, r := range rows {
			switch r.State {
			case "expiring", "expired":
				expiring[r.Domain] = true
				when := "soon"
				if r.NotAfter != nil {
					when = r.NotAfter.Format("2 Jan 2006 15:04 MST")
				}
				verb := "expires"
				if r.State == "expired" {
					verb = "expired"
				}
				errs = append(errs, m.raise(ctx, store.AlertCertExpiring, r.Domain,
					fmt.Sprintf("The certificate for %s %s %s.", r.Domain, verb, when)))
			}
			if r.LastError != nil && r.State != "valid" {
				failed[r.Domain] = true
				errs = append(errs, m.raise(ctx, store.AlertCertFailed, r.Domain,
					fmt.Sprintf("Caddy couldn't get a certificate for %s: %s", r.Domain, r.LastError.Message)))
			}
		}
		errs = append(errs, m.Store.ResolveAlertsExcept(ctx, store.AlertCertExpiring, expiring))
		errs = append(errs, m.Store.ResolveAlertsExcept(ctx, store.AlertCertFailed, failed))
	}

	snap.LogBytes = dirSize(m.LogDir)
	m.mu.Lock()
	m.snap = snap
	m.mu.Unlock()
	return errors.Join(errs...)
}

// Certs lists every domain that needs a certificate, with its status and
// Caddy's last error for it.
func (m *Monitor) Certs(ctx context.Context) ([]CertRow, error) {
	hosts, err := m.Store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	all, err := certs.Scan(m.CaddyDataDir)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	errsByName := make(map[string]CertError, len(m.certErrs))
	for k, v := range m.certErrs {
		errsByName[k] = v
	}
	m.mu.Unlock()
	now := time.Now()
	rows := []CertRow{}
	for _, h := range hosts {
		if !h.Enabled || h.TLSMode == store.TLSOff {
			continue
		}
		for _, d := range h.Domains {
			st := certs.For(d, all, now)
			r := CertRow{Domain: d, HostID: h.ID, TLSMode: h.TLSMode, State: st.State, Issuer: st.Issuer, NotAfter: st.NotAfter}
			if e, ok := errsByName[d]; ok && (st.NotAfter == nil || e.At.After(now.Add(-24*time.Hour))) {
				e := e
				r.LastError = &e
			}
			rows = append(rows, r)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Domain < rows[j].Domain })
	return rows, nil
}

// readTLSLog reads new lines from Caddy's certificate log and records the
// last error per name; a later success clears it.
func (m *Monitor) readTLSLog() {
	if m.TLSLogFile == "" {
		return
	}
	f, err := os.Open(m.TLSLogFile)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.certErrs == nil {
		m.certErrs = map[string]CertError{}
	}
	if info.Size() < m.logOffset {
		m.logOffset = 0 // rotated
	}
	if _, err := f.Seek(m.logOffset, io.SeekStart); err != nil {
		return
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var read int64
	for sc.Scan() {
		line := sc.Bytes()
		read += int64(len(line)) + 1
		var e struct {
			Level      string  `json:"level"`
			TS         float64 `json:"ts"`
			Msg        string  `json:"msg"`
			Identifier string  `json:"identifier"`
			Error      string  `json:"error"`
		}
		if json.Unmarshal(line, &e) != nil || e.Identifier == "" {
			continue
		}
		at := time.Unix(int64(e.TS), 0).UTC()
		switch {
		case strings.Contains(e.Msg, "obtained successfully"), strings.Contains(e.Msg, "renewed successfully"):
			delete(m.certErrs, e.Identifier)
		case e.Error != "" && (e.Level == "error" || e.Level == "warn"):
			m.certErrs[e.Identifier] = CertError{Message: e.Error, At: at}
		}
	}
	m.logOffset += read
}

func dirSize(dir string) int64 {
	if dir == "" {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // skip unreadable entries
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}
