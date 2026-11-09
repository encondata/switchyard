package server

import (
	"net/http"
	"sort"
	"time"

	"github.com/encondata/switchyard/internal/certs"
	"github.com/encondata/switchyard/internal/store"
)

// wildcardView is a wildcard certificate with its status and the hosts it
// covers.
type wildcardView struct {
	store.WildcardCert
	Status certs.Status `json:"status"`
	Hosts  []coveredRef `json:"hosts"`
}

type coveredRef struct {
	ID     int64  `json:"id"`
	Domain string `json:"domain"`
}

func (s *srv) handleListWildcards(w http.ResponseWriter, r *http.Request) {
	ws, err := s.store.ListWildcards(r.Context())
	if s.storeError(w, err) {
		return
	}
	hosts, err := s.store.ListHosts(r.Context())
	if s.storeError(w, err) {
		return
	}
	var all []certs.Cert
	if s.caddyDataDir != "" {
		all, _ = certs.Scan(s.caddyDataDir)
	}
	now := time.Now()
	out := make([]wildcardView, 0, len(ws))
	for _, wc := range ws {
		v := wildcardView{WildcardCert: wc, Status: certs.For("*."+wc.Domain, all, now), Hosts: []coveredRef{}}
		for _, h := range hosts {
			if h.TLSMode != store.TLSAuto && h.TLSMode != store.TLSDNS {
				continue
			}
			for _, d := range h.Domains {
				if wc.Covers(d) {
					v.Hosts = append(v.Hosts, coveredRef{ID: h.ID, Domain: d})
				}
			}
		}
		sort.Slice(v.Hosts, func(i, j int) bool { return v.Hosts[i].Domain < v.Hosts[j].Domain })
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *srv) handleSaveWildcard(w http.ResponseWriter, r *http.Request) {
	var wc store.WildcardCert
	if !decodeJSON(w, r, &wc) {
		return
	}
	wc.ID = 0
	status := http.StatusCreated
	if r.Method == http.MethodPut {
		id, ok := pathID(w, r, "id")
		if !ok {
			return
		}
		wc.ID, status = id, http.StatusOK
	}
	saved, err := s.store.SaveWildcard(r.Context(), wc, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, status, saved)
}

func (s *srv) handleDeleteWildcard(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.DeleteWildcard(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleReleaseHost takes a held host off its decoy now. It's live at once;
// no apply is needed.
func (s *srv) handleReleaseHost(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	h, err := s.store.GetHost(r.Context(), id)
	if s.storeError(w, err) {
		return
	}
	if h.HoldUntil == nil {
		writeError(w, http.StatusConflict, "conflict", "This host isn't on hold.")
		return
	}
	if err := s.apply.ReleaseHost(r.Context(), id, userFrom(r).Username); err != nil {
		writeError(w, http.StatusBadGateway, "release_failed", err.Error())
		return
	}
	s.log.Info("host released from hold", "host", id, "by", userFrom(r).Username)
	h, _ = s.store.GetHost(r.Context(), id)
	writeJSON(w, http.StatusOK, h)
}
