package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/encondata/switchyard/internal/store"
	"github.com/encondata/switchyard/internal/unifi"
)

type unifiBody struct {
	store.UniFiSettings
	APIKey string `json:"api_key"` // empty keeps the saved key
}

type unifiCheckBody struct {
	URL        string `json:"url"`
	APIKey     string `json:"api_key"`     // empty uses the saved key
	CertSHA256 string `json:"cert_sha256"` // the certificate the person trusts
}

// unifiCheckResult tells the page what to do next: trust the certificate,
// fix the key, or pick a site.
type unifiCheckResult struct {
	Cert             *unifi.CertInfo `json:"cert,omitempty"`
	Fingerprint      string          `json:"fingerprint,omitempty"`
	NeedsTrust       bool            `json:"needs_trust"`
	CertChanged      bool            `json:"cert_changed"`
	Sites            []unifi.Site    `json:"sites"`
	Error            string          `json:"error,omitempty"`
	PinnedCertSHA256 string          `json:"cert_sha256"`
}

func (s *srv) handleGetUniFi(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.UniFi(r.Context())
	if s.storeError(w, err) {
		return
	}
	st := unifi.Status{}
	if s.unifi != nil {
		st = s.unifi.Status()
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": u, "status": st, "fingerprint": unifi.Fingerprint(u.CertSHA256)})
}

func (s *srv) handlePutUniFi(w http.ResponseWriter, r *http.Request) {
	var req unifiBody
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.store.SaveUniFi(r.Context(), req.UniFiSettings, req.APIKey, s.box, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	if s.unifi != nil {
		// Sync now, so the page shows the result (or the error) straight away.
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		_ = s.unifi.Sync(ctx, true)
		writeJSON(w, http.StatusOK, map[string]any{"settings": u, "status": s.unifi.Status(), "fingerprint": unifi.Fingerprint(u.CertSHA256)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": u})
}

// handleCheckUniFi reads the console's certificate and, once it's trusted
// (valid, or matching the fingerprint the person confirmed), lists the
// sites with the API key. The key is never sent to an untrusted console.
func (s *srv) handleCheckUniFi(w http.ResponseWriter, r *http.Request) {
	var req unifiCheckBody
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	url := strings.TrimRight(strings.TrimSpace(req.URL), "/")
	if url != "" && !strings.Contains(url, "://") {
		url = "https://" + url
	}
	res := unifiCheckResult{Sites: []unifi.Site{}}
	cert, err := unifi.FetchCert(ctx, url)
	if err != nil {
		res.Error = err.Error()
		writeJSON(w, http.StatusOK, res)
		return
	}
	res.Cert, res.Fingerprint = &cert, unifi.Fingerprint(cert.SHA256)
	pin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.CertSHA256), ":", ""))
	if !cert.Valid {
		if pin == "" {
			res.NeedsTrust = true
			writeJSON(w, http.StatusOK, res)
			return
		}
		if pin != cert.SHA256 {
			res.NeedsTrust, res.CertChanged = true, true
			writeJSON(w, http.StatusOK, res)
			return
		}
		res.PinnedCertSHA256 = cert.SHA256
	}
	key := strings.TrimSpace(req.APIKey)
	if key == "" {
		if key, err = s.store.UniFiKey(r.Context(), s.box); s.storeError(w, err) {
			return
		}
	}
	if key == "" {
		res.Error = "paste the console's API key"
		writeJSON(w, http.StatusOK, res)
		return
	}
	sites, err := (&unifi.Client{BaseURL: url, APIKey: key, CertSHA256: res.PinnedCertSHA256}).Sites(ctx)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Sites = sites
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *srv) handleSyncUniFi(w http.ResponseWriter, r *http.Request) {
	if s.unifi == nil {
		writeError(w, http.StatusNotFound, "not_found", "UniFi sync isn't available.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	_ = s.unifi.Sync(ctx, true)
	writeJSON(w, http.StatusOK, s.unifi.Status())
}
