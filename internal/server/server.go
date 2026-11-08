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

	"github.com/encondata/switchyard/internal/apply"
	"github.com/encondata/switchyard/internal/caddyadmin"
	"github.com/encondata/switchyard/internal/geoip"
	"github.com/encondata/switchyard/internal/hits"
	"github.com/encondata/switchyard/internal/monitor"
	"github.com/encondata/switchyard/internal/ratelimit"
	"github.com/encondata/switchyard/internal/secrets"
	"github.com/encondata/switchyard/internal/store"
	"github.com/encondata/switchyard/internal/unifi"
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
	// GeoIP is the country database (for its age and lookups).
	GeoIP *geoip.DB
	// Hits is the traffic database (dashboard). Stats routes need it.
	Hits *hits.DB
	// Bans pushes the ban list to Caddy after manual changes.
	Bans BanPusher
	// UniFi keeps the ban list in a UniFi firewall (optional).
	UniFi *unifi.Syncer
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
	geo          *geoip.DB
	hits         *hits.DB
	topCache     topCache
	bans         BanPusher
	unifi        *unifi.Syncer
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
		geo:           opts.GeoIP,
		hits:          opts.Hits,
		bans:          opts.Bans,
		unifi:         opts.UniFi,
		ipFailures:    ratelimit.New(10, 15*time.Minute),
		userFailures:  ratelimit.New(5, 15*time.Minute),
	}
	// Usernames come from unauthenticated requests: track fewer of them.
	s.userFailures.MaxKeys = 10_000

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
	})
	mux.HandleFunc("GET /api/openapi.json", s.handleOpenAPI)
	// Every other endpoint comes from the operations list (operations.go),
	// which also drives API key permissions and the OpenAPI document.
	for _, rt := range s.routes() {
		if s.has(rt.needs) {
			mux.HandleFunc(rt.Method+" "+rt.Path, s.guard(rt.Op, rt.handler))
		}
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
