package server

import (
	"net/http"

	"github.com/encondata/caddyproxymanager/internal/store"
)

// handleGetPrefs returns the signed-in user's display preferences.
func (s *srv) handleGetPrefs(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetPrefs(r.Context(), userFrom(r).ID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handlePutPrefs saves the signed-in user's display preferences.
func (s *srv) handlePutPrefs(w http.ResponseWriter, r *http.Request) {
	var req store.Prefs
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.store.SetPrefs(r.Context(), userFrom(r).ID, req)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, p)
}
