package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/encondata/switchyard/internal/caddyadmin"
	"github.com/encondata/switchyard/internal/certs"
	"github.com/encondata/switchyard/internal/store"
)

// canEdit is true for roles that may change hosts and apply configs.
func canEdit(u store.User) bool { return u.Role == "admin" || u.Role == "editor" }

// requireEditor wraps requireUser and rejects viewers.
func (s *srv) requireEditor(next http.HandlerFunc) http.HandlerFunc {
	return s.requireUser(false, func(w http.ResponseWriter, r *http.Request) {
		if !canEdit(userFrom(r)) {
			writeError(w, http.StatusForbidden, "forbidden", "Your role can view but not change settings.")
			return
		}
		next(w, r)
	})
}

// requireAdmin wraps requireUser and allows only admins (credentials and
// user management).
func (s *srv) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireUser(false, func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r).Role != "admin" {
			writeError(w, http.StatusForbidden, "forbidden", "Only admins can do this.")
			return
		}
		next(w, r)
	})
}

func pathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return 0, false
	}
	return id, true
}

// hostView is a host plus its certificate status, for the hosts list.
type hostView struct {
	store.Host
	Certs []certs.Status `json:"certs"`
}

func (s *srv) handleListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.store.ListHosts(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	all, err := certs.Scan(s.caddyDataDir)
	if err != nil {
		s.log.Warn("scanning certificates", "err", err)
	}
	now := time.Now()
	out := make([]hostView, 0, len(hosts))
	for _, h := range hosts {
		v := hostView{Host: h, Certs: []certs.Status{}}
		for _, d := range h.Domains {
			st := certs.Status{Domain: d, State: "not_needed"}
			if h.TLSMode != store.TLSOff {
				st = certs.For(d, all, now)
			}
			v.Certs = append(v.Certs, st)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *srv) handleGetHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	h, err := s.store.GetHost(r.Context(), id)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *srv) handleSaveHost(w http.ResponseWriter, r *http.Request) {
	var h store.Host
	if !decodeJSON(w, r, &h) {
		return
	}
	h.ID = 0
	status := http.StatusCreated
	if r.Method == http.MethodPut {
		id, ok := pathID(w, r, "id")
		if !ok {
			return
		}
		h.ID = id
		status = http.StatusOK
	}
	// The advanced snippet can do anything Caddy can (serve files, call
	// other services), so the store only lets admins set it or change hosts
	// that have one.
	u := userFrom(r)
	saved, err := s.store.SaveHostAs(r.Context(), h, u.Username, u.Role == "admin")
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, status, saved)
}

func (s *srv) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.DeleteHost(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *srv) handlePreview(w http.ResponseWriter, r *http.Request) {
	p, err := s.apply.Preview(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *srv) handleApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	v, err := s.apply.Apply(ctx, userFrom(r).Username, req.Note)
	s.applyResult(w, v, err)
}

func (s *srv) handleRollback(w http.ResponseWriter, r *http.Request) {
	n, ok := pathID(w, r, "n")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	v, err := s.apply.Rollback(ctx, n, userFrom(r).Username)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "No such config version.")
		return
	}
	s.applyResult(w, v, err)
}

func (s *srv) applyResult(w http.ResponseWriter, v store.ConfigVersion, err error) {
	v.JSON = ""
	var le *caddyadmin.LoadError
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, v)
	case errors.As(err, &le):
		// Caddy refused the config and is still running the previous one.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "caddy_rejected", "message": le.Message, "version": v,
		})
	case v.Result == "failed":
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "caddy_unreachable", "message": err.Error(), "version": v,
		})
	default:
		s.internalError(w, err)
	}
}

func (s *srv) handleListVersions(w http.ResponseWriter, r *http.Request) {
	vs, err := s.store.ListConfigVersions(r.Context(), 100)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vs)
}

func (s *srv) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	n, ok := pathID(w, r, "n")
	if !ok {
		return
	}
	v, err := s.store.GetConfigVersion(r.Context(), n)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *srv) handleVersionDiff(w http.ResponseWriter, r *http.Request) {
	n, ok := pathID(w, r, "n")
	if !ok {
		return
	}
	diff, prev, err := s.apply.VersionDiff(r.Context(), n)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"diff": diff, "previous": prev})
}

// storeError writes the response for a store error and reports whether
// there was one.
func (s *srv) storeError(w http.ResponseWriter, err error) bool {
	var verr store.ValidationError
	var conflict store.ConflictError
	switch {
	case err == nil:
		return false
	case errors.As(err, &conflict):
		writeError(w, http.StatusConflict, "conflict", conflict.Error())
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	case errors.As(err, &verr):
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid", "message": "Fix the highlighted fields.", "fields": verr,
		})
	default:
		s.internalError(w, err)
	}
	return true
}
