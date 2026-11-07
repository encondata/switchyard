// Command cpm runs the CaddyProxyManager server: the HTTP API and the
// embedded web UI.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/encondata/caddyproxymanager/internal/caddyadmin"
	"github.com/encondata/caddyproxymanager/internal/server"
	"github.com/encondata/caddyproxymanager/internal/store"
	"github.com/encondata/caddyproxymanager/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	listen := flag.String("listen", envOr("CPM_LISTEN", "0.0.0.0:8080"), "address for the API and web UI")
	dataDir := flag.String("data", envOr("CPM_DATA_DIR", "./data"), "directory for the CPM database")
	caddySocket := flag.String("caddy-admin-socket", os.Getenv("CPM_CADDY_ADMIN_SOCKET"), "path to Caddy's admin unix socket")
	secureCookies := flag.Bool("secure-cookies", os.Getenv("CPM_SECURE_COOKIES") == "true", "mark session cookies Secure (when CPM is served over HTTPS)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(*dataDir, 0o750); err != nil {
		logger.Error("creating data dir", "err", err)
		os.Exit(1)
	}
	st, err := store.Open(ctx, filepath.Join(*dataDir, "cpm.db"))
	if err != nil {
		logger.Error("opening database", "err", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()
	if created, err := st.EnsureDefaultAdmin(ctx); err != nil {
		logger.Error("creating default admin", "err", err)
		os.Exit(1)
	} else if created {
		logger.Warn("created default account; it must change its password at first sign-in",
			"username", store.DefaultAdminUsername)
	}
	go func() {
		for range time.Tick(time.Hour) {
			_ = st.DeleteExpiredSessions(context.Background())
		}
	}()

	var caddy *caddyadmin.Client
	if *caddySocket != "" {
		caddy = caddyadmin.New(*caddySocket)
	}

	srv := &http.Server{
		Addr: *listen,
		Handler: server.New(server.Options{
			Version: version, UI: web.Dist(), Logger: logger,
			Store: st, Caddy: caddy, SecureCookies: *secureCookies,
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("cpm listening", "addr", *listen, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown failed", "err", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
