// Package server wires up the CPM HTTP API and serves the embedded web UI.
package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/encondata/caddyproxymanager/internal/caddyadmin"
	"github.com/encondata/caddyproxymanager/internal/store"
)

// Options configures the HTTP handler.
type Options struct {
	Version string
	// UI holds the built frontend (index.html at its root). May be nil.
	UI     fs.FS
	Logger *slog.Logger
	Store  *store.Store
	// Caddy is the admin API client. May be nil if Caddy isn't configured.
	Caddy *caddyadmin.Client
	// SecureCookies marks the session cookie Secure (set when CPM is served
	// over HTTPS).
	SecureCookies bool
}

type srv struct {
	version       string
	log           *slog.Logger
	store         *store.Store
	caddy         *caddyadmin.Client
	secureCookies bool
}

// New returns the root HTTP handler.
func New(opts Options) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &srv{
		version:       opts.Version,
		log:           opts.Logger,
		store:         opts.Store,
		caddy:         opts.Caddy,
		secureCookies: opts.SecureCookies,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
	})
	if s.store != nil {
		mux.HandleFunc("POST /api/auth/login", s.handleLogin)
		mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
		mux.HandleFunc("GET /api/auth/me", s.requireUser(true, s.handleMe))
		mux.HandleFunc("POST /api/auth/password", s.requireUser(true, s.handleChangePassword))
		mux.HandleFunc("GET /api/status", s.requireUser(false, s.handleStatus))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	})
	mux.Handle("/", spaHandler(opts.UI))
	return securityHeaders(mux)
}

// handleStatus reports whether CPM can reach Caddy's admin API.
func (s *srv) handleStatus(w http.ResponseWriter, r *http.Request) {
	type caddyStatus struct {
		Reachable bool   `json:"reachable"`
		Socket    string `json:"socket,omitempty"`
		Error     string `json:"error,omitempty"`
	}
	cs := caddyStatus{}
	if s.caddy == nil {
		cs.Error = "Caddy admin socket not configured (CPM_CADDY_ADMIN_SOCKET)"
	} else {
		cs.Socket = s.caddy.Socket()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, err := s.caddy.Config(ctx); err != nil {
			cs.Error = err.Error()
		} else {
			cs.Reachable = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": s.version, "caddy": cs})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// spaHandler serves static files from ui and falls back to index.html for
// client-side routes, so deep links into the React app work.
func spaHandler(ui fs.FS) http.Handler {
	if ui == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "web UI not built; run `make ui`", http.StatusServiceUnavailable)
		})
	}
	files := http.FileServerFS(ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(ui, name); err != nil {
			// Unknown path without a file extension: treat as an app route.
			if path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		files.ServeHTTP(w, r)
	})
}

func (s *srv) internalError(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "Something went wrong. Check the CPM logs.")
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
