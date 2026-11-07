package server

import (
	"context"
	"net/http"
	"time"

	"github.com/encondata/caddyproxymanager/internal/cloudflare"
	"github.com/encondata/caddyproxymanager/internal/store"
)

func (s *srv) handleListDNSProviders(w http.ResponseWriter, r *http.Request) {
	ps, err := s.store.ListDNSProviders(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"providers":     ps,
		"secrets_ready": s.box.Ready(),
	})
}

func (s *srv) handleSaveDNSProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		APIToken string `json:"api_token"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	p := store.DNSProvider{Name: req.Name, Type: req.Type}
	status := http.StatusCreated
	if r.Method == http.MethodPut {
		id, ok := pathID(w, r, "id")
		if !ok {
			return
		}
		p.ID, status = id, http.StatusOK
	}
	saved, err := s.store.SaveDNSProvider(r.Context(), p, req.APIToken, s.box, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, status, saved)
}

func (s *srv) handleDeleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.DeleteDNSProvider(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleVerifyDNSProvider asks Cloudflare whether the stored token works and
// which zones it can manage.
func (s *srv) handleVerifyDNSProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	tok, err := s.store.DNSToken(r.Context(), id, s.box)
	if s.storeError(w, err) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := cloudflare.Verify(ctx, tok)
	if err != nil {
		writeError(w, http.StatusBadGateway, "verify_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
