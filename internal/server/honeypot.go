package server

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/encondata/caddyproxymanager/internal/store"
)

// BanPusher sends bans to Caddy right away.
type BanPusher interface {
	ForcePush(ctx context.Context) error
}

func (s *srv) handleGetHoneypot(w http.ResponseWriter, r *http.Request) {
	hp, err := s.store.Honeypot(r.Context())
	if s.storeError(w, err) {
		return
	}
	traps, err := s.store.ListTrapPaths(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": hp, "traps": traps})
}

func (s *srv) handlePutHoneypot(w http.ResponseWriter, r *http.Request) {
	var hp store.HoneypotSettings
	if !decodeJSON(w, r, &hp) {
		return
	}
	saved, err := s.store.SaveHoneypot(r.Context(), hp, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *srv) handleSaveTrap(w http.ResponseWriter, r *http.Request) {
	var t store.TrapPath
	if !decodeJSON(w, r, &t) {
		return
	}
	t.ID = 0
	if r.Method == http.MethodPut {
		id, ok := pathID(w, r, "id")
		if !ok {
			return
		}
		t.ID = id
	}
	saved, err := s.store.SaveTrapPath(r.Context(), t, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *srv) handleDeleteTrap(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.DeleteTrapPath(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *srv) handleHoneypotActivity(w http.ResponseWriter, r *http.Request) {
	from, to, _, err := s.statsScope(r)
	if s.storeError(w, err) {
		return
	}
	out := map[string]any{}
	for _, dim := range []string{"path", "ip", "ua", "host"} {
		rows, err := s.hits.HoneypotTop(r.Context(), dim, from, to, 15)
		if s.storeError(w, err) {
			return
		}
		out[dim] = rows
	}
	recent, err := s.hits.HoneypotRecent(r.Context(), 100)
	if s.storeError(w, err) {
		return
	}
	out["recent"] = recent
	writeJSON(w, http.StatusOK, out)
}

func (s *srv) handleListBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.store.ListBans(r.Context(), r.URL.Query().Get("all") == "", 1000)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, bans)
}

func (s *srv) pushBans(ctx context.Context) string {
	if s.bans == nil {
		return "Caddy isn't connected, so the ban list wasn't sent."
	}
	if err := s.bans.ForcePush(ctx); err != nil {
		return "Saved, but sending the ban list to Caddy failed: " + err.Error()
	}
	return ""
}

func (s *srv) handleAddBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR   string `json:"cidr"`
		Reason string `json:"reason"`
		Days   int    `json:"days"` // 0 = until removed
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Days < 0 || req.Days > 3650 {
		writeError(w, http.StatusBadRequest, "bad_request", "Ban for 0 (until removed) to 3650 days.")
		return
	}
	if len(req.Reason) > 300 {
		req.Reason = req.Reason[:300]
	}
	b, err := s.store.AddBan(r.Context(), req.CIDR, req.Reason, "manual", time.Duration(req.Days)*24*time.Hour, 0, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ban": b, "warning": s.pushBans(r.Context())})
}

func (s *srv) handleRemoveBan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.RemoveBan(r.Context(), id, userFrom(r).Username)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"warning": s.pushBans(r.Context())})
}

func (s *srv) handleUnbanAddress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	n, err := s.store.UnbanAddress(r.Context(), req.CIDR, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lifted": n, "warning": s.pushBans(r.Context())})
}

// handleExportBans downloads bans as CSV or JSON (spec F6).
func (s *srv) handleExportBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.store.ListBans(r.Context(), r.URL.Query().Get("all") == "", 100000)
	if s.storeError(w, err) {
		return
	}
	name := "cpm-bans-" + time.Now().UTC().Format("20060102")
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		writeJSON(w, http.StatusOK, bans)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"cidr", "source", "reason", "created_by", "created_at", "expires_at", "active", "hits"})
	for _, b := range bans {
		exp := ""
		if b.ExpiresAt != nil {
			exp = b.ExpiresAt.UTC().Format(time.RFC3339)
		}
		// Neutralize spreadsheet formulas in free text.
		reason := b.Reason
		if reason != "" && (reason[0] == '=' || reason[0] == '+' || reason[0] == '-' || reason[0] == '@') {
			reason = "'" + reason
		}
		_ = cw.Write([]string{b.CIDR, b.Source, reason, b.CreatedBy, b.CreatedAt.UTC().Format(time.RFC3339), exp,
			strconv.FormatBool(b.Active), fmt.Sprint(b.HitCount)})
	}
	cw.Flush()
}
