// Package server wires up the CPM HTTP API and serves the embedded web UI.
package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/encondata/caddyproxymanager/internal/apply"
	"github.com/encondata/caddyproxymanager/internal/caddyadmin"
	"github.com/encondata/caddyproxymanager/internal/monitor"
	"github.com/encondata/caddyproxymanager/internal/ratelimit"
	"github.com/encondata/caddyproxymanager/internal/secrets"
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
	// Apply builds and applies Caddy configs. Host and config routes are only
	// registered when it is set.
	Apply *apply.Service
	// CaddyDataDir is Caddy's data folder (mounted read-only), for cert status.
	CaddyDataDir string
	// Box seals DNS provider tokens. Nil when CPM_SECRET_KEY isn't set.
	Box *secrets.Box
	// Monitor runs background checks; required with Apply.
	Monitor *monitor.Monitor
	// DataDir holds the database (backups, restores).
	DataDir string
	// Restart stops the server so it restarts (after a restore).
	Restart func()
}

type srv struct {
	version       string
	log           *slog.Logger
	store         *store.Store
	caddy         *caddyadmin.Client
	secureCookies bool
	apply         *apply.Service
	caddyDataDir  string
	box           *secrets.Box
	monitor       *monitor.Monitor
	dataDir       string
	restart       func()
	// Failed sign-ins: 10 per IP and 5 per username in 15 minutes.
	ipFailures   *ratelimit.Failures
	userFailures *ratelimit.Failures
	imports      pendingImports
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
		apply:         opts.Apply,
		caddyDataDir:  opts.CaddyDataDir,
		box:           opts.Box,
		monitor:       opts.Monitor,
		dataDir:       opts.DataDir,
		restart:       opts.Restart,
		ipFailures:    ratelimit.New(10, 15*time.Minute),
		userFailures:  ratelimit.New(5, 15*time.Minute),
	}
	// Usernames come from unauthenticated requests: track fewer of them.
	s.userFailures.MaxKeys = 10_000

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
	})
	if s.store != nil {
		mux.HandleFunc("POST /api/auth/login", s.handleLogin)
		mux.HandleFunc("POST /api/auth/totp", s.handleLoginTOTP)
		mux.HandleFunc("GET /api/auth/2fa", s.requireUser(true, s.handle2FAStatus))
		mux.HandleFunc("POST /api/auth/2fa/begin", s.requireUser(true, s.handle2FABegin))
		mux.HandleFunc("POST /api/auth/2fa/confirm", s.requireUser(true, s.handle2FAConfirm))
		mux.HandleFunc("POST /api/auth/2fa/disable", s.requireUser(false, s.handle2FADisable))
		mux.HandleFunc("GET /api/users", s.requireAdmin(s.handleListUsers))
		mux.HandleFunc("POST /api/users", s.requireAdmin(s.handleCreateUser))
		mux.HandleFunc("PUT /api/users/{id}", s.requireAdmin(s.handleUpdateUser))
		mux.HandleFunc("POST /api/users/{id}/password", s.requireAdmin(s.handleResetUserPassword))
		mux.HandleFunc("POST /api/users/{id}/reset-2fa", s.requireAdmin(s.handleResetUser2FA))
		mux.HandleFunc("DELETE /api/users/{id}", s.requireAdmin(s.handleDeleteUser))
		mux.HandleFunc("GET /api/settings", s.requireAdmin(s.handleGetSettings))
		mux.HandleFunc("PUT /api/settings", s.requireAdmin(s.handlePutSettings))
		mux.HandleFunc("GET /api/audit", s.requireAdmin(s.handleAudit))
		mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
		mux.HandleFunc("GET /api/auth/me", s.requireUser(true, s.handleMe))
		mux.HandleFunc("POST /api/auth/password", s.requireUser(true, s.handleChangePassword))
		mux.HandleFunc("GET /api/status", s.requireUser(false, s.handleStatus))
	}
	if s.store != nil && s.apply != nil {
		mux.HandleFunc("GET /api/hosts", s.requireUser(false, s.handleListHosts))
		mux.HandleFunc("POST /api/hosts", s.requireEditor(s.handleSaveHost))
		mux.HandleFunc("GET /api/hosts/{id}", s.requireUser(false, s.handleGetHost))
		mux.HandleFunc("PUT /api/hosts/{id}", s.requireEditor(s.handleSaveHost))
		mux.HandleFunc("DELETE /api/hosts/{id}", s.requireEditor(s.handleDeleteHost))
		mux.HandleFunc("GET /api/config/preview", s.requireUser(false, s.handlePreview))
		mux.HandleFunc("POST /api/config/apply", s.requireEditor(s.handleApply))
		mux.HandleFunc("GET /api/config/versions", s.requireUser(false, s.handleListVersions))
		mux.HandleFunc("GET /api/config/versions/{n}", s.requireUser(false, s.handleGetVersion))
		mux.HandleFunc("POST /api/config/versions/{n}/rollback", s.requireEditor(s.handleRollback))

		mux.HandleFunc("GET /api/folders", s.requireUser(false, s.handleListFolders))
		mux.HandleFunc("POST /api/folders", s.requireEditor(s.handleSaveFolder))
		mux.HandleFunc("PUT /api/folders/{id}", s.requireEditor(s.handleSaveFolder))
		mux.HandleFunc("DELETE /api/folders/{id}", s.requireEditor(s.handleDeleteFolder))
		mux.HandleFunc("POST /api/folders/{id}/enabled", s.requireEditor(s.handleFolderEnabled))
		mux.HandleFunc("POST /api/hosts/{id}/move", s.requireEditor(s.handleMoveHost))
		mux.HandleFunc("GET /api/policies", s.requireUser(false, s.handleListPolicies))
		mux.HandleFunc("POST /api/policies", s.requireEditor(s.handleSavePolicy))
		mux.HandleFunc("PUT /api/policies/{id}", s.requireEditor(s.handleSavePolicy))
		mux.HandleFunc("DELETE /api/policies/{id}", s.requireEditor(s.handleDeletePolicy))
		mux.HandleFunc("GET /api/never-ban", s.requireUser(false, s.handleListNeverBan))
		mux.HandleFunc("POST /api/never-ban", s.requireEditor(s.handleAddNeverBan))
		mux.HandleFunc("DELETE /api/never-ban", s.requireEditor(s.handleDeleteNeverBan))
		mux.HandleFunc("GET /api/whoami", s.requireUser(false, s.handleWhoAmI))
		mux.HandleFunc("GET /api/dns-providers", s.requireUser(false, s.handleListDNSProviders))
		mux.HandleFunc("POST /api/dns-providers", s.requireAdmin(s.handleSaveDNSProvider))
		mux.HandleFunc("PUT /api/dns-providers/{id}", s.requireAdmin(s.handleSaveDNSProvider))
		mux.HandleFunc("DELETE /api/dns-providers/{id}", s.requireAdmin(s.handleDeleteDNSProvider))
		mux.HandleFunc("POST /api/dns-providers/{id}/verify", s.requireEditor(s.handleVerifyDNSProvider))
		mux.HandleFunc("GET /api/certificates", s.requireUser(false, s.handleCertificates))
		mux.HandleFunc("POST /api/certificates/retry", s.requireEditor(s.handleRetryCerts))
	}
	if s.store != nil && s.monitor != nil {
		mux.HandleFunc("GET /api/alerts", s.requireUser(false, s.handleAlerts))
		mux.HandleFunc("GET /api/health/details", s.requireUser(false, s.handleHealth))
		mux.HandleFunc("POST /api/health/check", s.requireUser(false, s.handleCheckNow))
		mux.HandleFunc("GET /api/backup", s.requireAdmin(s.handleBackup))
		mux.HandleFunc("POST /api/restore", s.requireAdmin(s.handleRestore))
		mux.HandleFunc("POST /api/import/npm/preview", s.requireAdmin(s.handleImportPreview))
		mux.HandleFunc("POST /api/import/npm/run", s.requireAdmin(s.handleImportRun))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	})
	mux.Handle("/", spaHandler(opts.UI))
	return securityHeaders(sameOrigin(mux))
}

// sameOrigin rejects state-changing API requests that a browser marks as
// coming from another site. It backs up the SameSite=Strict session cookie
// for endpoints with no JSON body (apply, rollback, delete, logout).
// Non-browser clients send neither header and aren't a CSRF risk.
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			writeError(w, http.StatusForbidden, "cross_site", "Cross-site requests are not allowed.")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				writeError(w, http.StatusForbidden, "cross_site", "Cross-site requests are not allowed.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
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

// clientIP is the TCP peer address. CPM isn't behind a proxy, so
// X-Forwarded-For is ignored (it could be forged).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

var randRead = rand.Read
