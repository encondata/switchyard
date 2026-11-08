package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/encondata/switchyard/internal/store"
)

// RestoreFile is where an uploaded backup waits; cpm swaps it in on the
// next start (see cmd/cpm).
const RestoreFile = "cpm.db.restore"

// maxBackup caps an uploaded backup.
const maxBackup = 512 << 20

func (s *srv) handleAlerts(w http.ResponseWriter, r *http.Request) {
	openOnly := r.URL.Query().Get("all") == ""
	as, err := s.store.ListAlerts(r.Context(), openOnly, 200)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, as)
}

// handleHealth is the health page: Caddy, last apply, drift, log disk use,
// database size and open alerts (spec F7).
func (s *srv) handleHealth(w http.ResponseWriter, r *http.Request) {
	snap := s.monitor.Snapshot()
	alerts, err := s.store.ListAlerts(r.Context(), true, 200)
	if s.storeError(w, err) {
		return
	}
	var dbBytes int64
	if info, err := os.Stat(filepath.Join(s.dataDir, "cpm.db")); err == nil {
		dbBytes = info.Size()
	}
	geo := map[string]any{"installed": false}
	if mt, ok := s.geo.ModTime(); ok {
		geo = map[string]any{"installed": true, "updated_at": mt.UTC(), "age_days": int(time.Since(mt).Hours() / 24)}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       s.version,
		"monitor":       snap,
		"alerts":        alerts,
		"db_bytes":      dbBytes,
		"secrets_ready": s.box.Ready(),
		"geoip":         geo,
	})
}

func (s *srv) handleCheckNow(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.monitor.Check(ctx); err != nil {
		s.log.Warn("check now", "err", err)
	}
	s.handleHealth(w, r)
}

func (s *srv) handleCertificates(w http.ResponseWriter, r *http.Request) {
	rows, err := s.monitor.Certs(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleRetryCerts makes Caddy try failed certificates again now.
func (s *srv) handleRetryCerts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.apply.Retry(ctx); err != nil {
		writeError(w, http.StatusBadGateway, "retry_failed", err.Error())
		return
	}
	s.log.Info("certificate retry requested", "username", userFrom(r).Username)
	w.WriteHeader(http.StatusNoContent)
}

// handleBackup downloads a consistent copy of the database.
func (s *srv) handleBackup(w http.ResponseWriter, r *http.Request) {
	dir, err := os.MkdirTemp(s.dataDir, ".backup-")
	if err != nil {
		s.internalError(w, err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "cpm.db")
	if err := s.store.Backup(r.Context(), path); err != nil {
		s.internalError(w, err)
		return
	}
	f, err := os.Open(path) //nolint:gosec // our own temp file
	if err != nil {
		s.internalError(w, err)
		return
	}
	defer func() { _ = f.Close() }()
	name := fmt.Sprintf("cpm-backup-%s.db", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	s.log.Info("backup downloaded", "username", userFrom(r).Username)
	_, _ = io.Copy(w, f)
}

// handleRestore takes a backup file as the raw request body, checks it,
// and stages it; CPM then restarts and swaps it in.
func (s *srv) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/vnd.sqlite3" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "Upload the backup file (Content-Type: application/vnd.sqlite3).")
		return
	}
	tmp, err := os.CreateTemp(s.dataDir, ".restore-*.db")
	if err != nil {
		s.internalError(w, err)
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	n, err := io.Copy(tmp, http.MaxBytesReader(w, r.Body, maxBackup))
	_ = tmp.Close()
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Upload failed or the file is larger than 512 MB.")
		return
	}
	if err := store.ValidateBackup(r.Context(), tmp.Name()); s.storeError(w, err) {
		return
	}
	if err := os.Rename(tmp.Name(), filepath.Join(s.dataDir, RestoreFile)); err != nil {
		s.internalError(w, err)
		return
	}
	s.log.Warn("backup staged for restore; restarting", "username", userFrom(r).Username, "bytes", n)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"message": "Backup accepted. CPM is restarting to restore it; sign in again in a few seconds.",
	})
	if s.restart != nil {
		go func() {
			time.Sleep(500 * time.Millisecond)
			s.restart()
		}()
	}
}
