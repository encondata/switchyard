package server

import (
	"net/http"

	"github.com/encondata/switchyard/internal/store"
)

func (s *srv) handleListFolders(w http.ResponseWriter, r *http.Request) {
	fs, err := s.store.ListFolders(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, fs)
}

func (s *srv) handleSaveFolder(w http.ResponseWriter, r *http.Request) {
	var f store.Folder
	if !decodeJSON(w, r, &f) {
		return
	}
	f.ID = 0
	status := http.StatusCreated
	if r.Method == http.MethodPut {
		id, ok := pathID(w, r, "id")
		if !ok {
			return
		}
		f.ID, status = id, http.StatusOK
	}
	saved, err := s.store.SaveFolder(r.Context(), f, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, status, saved)
}

func (s *srv) handleDeleteFolder(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.DeleteFolder(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *srv) handleFolderEnabled(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	n, err := s.store.SetFolderEnabled(r.Context(), id, req.Enabled, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"hosts_changed": n})
}

func (s *srv) handleMoveHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		FolderID *int64 `json:"folder_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u := userFrom(r)
	h, err := s.store.MoveHost(r.Context(), id, req.FolderID, u.Username, u.Role == "admin")
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *srv) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := s.store.ListPolicies(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, ps)
}

func (s *srv) handleSavePolicy(w http.ResponseWriter, r *http.Request) {
	var p store.AccessPolicy
	if !decodeJSON(w, r, &p) {
		return
	}
	p.ID = 0
	status := http.StatusCreated
	if r.Method == http.MethodPut {
		id, ok := pathID(w, r, "id")
		if !ok {
			return
		}
		p.ID, status = id, http.StatusOK
	}
	saved, err := s.store.SavePolicy(r.Context(), p, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, status, saved)
}

func (s *srv) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.DeletePolicy(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *srv) handleListNeverBan(w http.ResponseWriter, r *http.Request) {
	nb, err := s.store.ListNeverBan(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, nb)
}

func (s *srv) handleAddNeverBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CIDR string `json:"cidr"`
		Note string `json:"note"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	nb, err := s.store.AddNeverBan(r.Context(), req.CIDR, req.Note, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	if s.unifi != nil {
		s.unifi.Trigger() // the firewall list must stop blocking it
	}
	writeJSON(w, http.StatusCreated, nb)
}

// handleDeleteNeverBan takes the address as ?cidr=, since CIDRs contain "/".
func (s *srv) handleDeleteNeverBan(w http.ResponseWriter, r *http.Request) {
	if s.storeError(w, s.store.DeleteNeverBan(r.Context(), r.URL.Query().Get("cidr"), userFrom(r).Username)) {
		return
	}
	if s.unifi != nil {
		s.unifi.Trigger()
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleWhoAmI returns the caller's IP as CPM sees it, so the UI can offer
// to add it to the never-block list. CPM is reached directly (not through
// Caddy), so this is the address of the machine running the browser, as
// seen from the CPM container.
func (s *srv) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"ip": clientIP(r)})
}
