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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/encondata/switchyard/internal/apply"
	"github.com/encondata/switchyard/internal/caddyadmin"
	"github.com/encondata/switchyard/internal/compiler"
	"github.com/encondata/switchyard/internal/geoip"
	"github.com/encondata/switchyard/internal/hits"
	"github.com/encondata/switchyard/internal/honeypot"
	"github.com/encondata/switchyard/internal/monitor"
	"github.com/encondata/switchyard/internal/secrets"
	"github.com/encondata/switchyard/internal/server"
	"github.com/encondata/switchyard/internal/store"
	"github.com/encondata/switchyard/web"
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
	dbPath := filepath.Join(*dataDir, "cpm.db")
	restored, err := swapInRestore(*dataDir, dbPath, logger)
	if err != nil {
		logger.Error("restoring backup", "err", err)
		os.Exit(1)
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		logger.Error("opening database", "err", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()
	if restored {
		// Sessions in the backup may have been revoked since it was taken.
		if err := st.ClearSessions(ctx); err != nil {
			logger.Error("clearing sessions after restore", "err", err)
			os.Exit(1)
		}
		logger.Warn("backup restored; everyone must sign in again")
	}
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
	var caddyAPI apply.Caddy = noCaddy{}
	if *caddySocket != "" {
		caddy = caddyadmin.New(*caddySocket)
		caddyAPI = caddy
	}
	adminListen := os.Getenv("CPM_CADDY_ADMIN_LISTEN")
	if adminListen == "" {
		socket := *caddySocket
		if socket == "" {
			socket = "/run/caddy/admin.sock"
		}
		adminListen = "unix/" + socket + "|0660"
	}
	box, err := secrets.New(os.Getenv("CPM_SECRET_KEY"))
	if err != nil {
		logger.Error("CPM_SECRET_KEY", "err", err)
		os.Exit(1)
	}
	if !box.Ready() {
		logger.Warn("CPM_SECRET_KEY is not set; DNS provider tokens can't be stored")
	}
	secretsDir := envOr("CPM_SECRETS_DIR", "/run/cpm-secrets")
	// Countries: MaxMind GeoLite2 if installed (geoipupdate), otherwise
	// DB-IP's free database, which CPM downloads next to the config it
	// writes for Caddy, so Caddy can read it for country rules too.
	geoDownloadDir := *dataDir
	if f := os.Getenv("CPM_CADDY_CONFIG_FILE"); f != "" {
		geoDownloadDir = filepath.Dir(f)
	}
	geoUpdater := &geoip.Updater{Dir: envOr("CPM_GEOIP_DOWNLOAD_DIR", geoDownloadDir),
		MaxMindPath: envOr("CPM_GEOIP_DB", "/usr/share/GeoIP/GeoLite2-Country.mmdb"), Log: logger}
	geo := &geoip.DB{Path: geoUpdater.MaxMindPath, Fallback: geoUpdater.Path()}
	applier := &apply.Service{
		Store: st,
		Caddy: caddyAPI,
		Settings: compiler.Settings{
			AdminListen:      adminListen,
			SecretsDir:       secretsDir,
			ACMECA:           os.Getenv("CPM_ACME_CA"),
			ACMEEmail:        os.Getenv("CPM_ACME_EMAIL"),
			ACMETrustedRoots: splitList(os.Getenv("CPM_ACME_CA_ROOTS")),
			TLSLogFile:       envOr("CPM_CADDY_TLS_LOG", "/var/log/caddy/tls.log"),
			GeoIPDB:          envOr("CPM_CADDY_GEOIP_DB", "/usr/share/GeoIP/GeoLite2-Country.mmdb"),
			AccessLogFile:    envOr("CPM_CADDY_ACCESS_LOG", "/var/log/caddy/access.log"),
		},
		GeoIP: geo,
		// Where Caddy sees the DB-IP file (CPM's config folder, mounted at
		// /etc/caddy/cpm in the Caddy container).
		CaddyFallbackGeoIPDB: envOr("CPM_CADDY_DBIP_DB", "/etc/caddy/cpm/"+geoip.DBIPFile),
		ConfigFile:           os.Getenv("CPM_CADDY_CONFIG_FILE"),
		Box:                  box,
		SecretsDir:           secretsDir,
	}
	// Caddy may restart with a config that reads token files; make sure
	// they exist.
	if err := applier.SyncSecrets(ctx); err != nil {
		logger.Warn("writing DNS provider tokens", "err", err)
	}

	// Traffic: Caddy's access log → hits.db (its own file, so config
	// backups stay small).
	hitsDB, err := hits.Open(ctx, filepath.Join(*dataDir, "hits.db"))
	if err != nil {
		logger.Error("opening hits database", "err", err)
		os.Exit(1)
	}
	defer func() { _ = hitsDB.Close() }()
	retainDays, _ := strconv.Atoi(os.Getenv("CPM_HIT_RETENTION_DAYS"))
	scorer := &honeypot.Scorer{Store: st, Pusher: applier, Log: logger}
	ingester := &hits.Ingester{
		DB: hitsDB, File: envOr("CPM_ACCESS_LOG", "/var/log/caddy/access.log"), Geo: geo, Log: logger,
		RetainHits: time.Duration(retainDays) * 24 * time.Hour,
		OnHits:     scorer.HandleHits,
	}
	go ingester.Run(ctx)
	// Requests logged before a country database was there get their
	// country once one is (at start, and after each download).
	fillCountries := func() {
		if !geo.Available() {
			return
		}
		if n, err := hitsDB.FillCountries(ctx, geo.Locate); err != nil {
			logger.Warn("filling in countries", "err", err)
		} else if n > 0 {
			logger.Info("filled in countries for earlier requests", "requests", n)
		}
	}
	if os.Getenv("CPM_GEOIP_DOWNLOAD") != "off" {
		geoUpdater.OnUpdate = fillCountries
		go geoUpdater.Run(ctx)
	}
	go fillCountries()
	if caddy != nil {
		go scorer.Maintain(ctx)
	}

	var mon *monitor.Monitor
	if caddy != nil {
		mon = &monitor.Monitor{
			Store: st, Caddy: caddy, CaddyDataDir: envOr("CPM_CADDY_DATA_DIR", "/caddy-data"),
			TLSLogFile: envOr("CPM_CADDY_TLS_LOG", "/var/log/caddy/tls.log"),
			LogDir:     envOr("CPM_CADDY_LOG_DIR", "/var/log/caddy"),
			Notifier:   monitor.LogNotifier{Log: logger}, Log: logger,
		}
		go mon.Run(ctx)
	}

	srv := &http.Server{
		Addr: *listen,
		Handler: server.New(server.Options{
			Version: version, UI: web.Dist(), Logger: logger,
			Store: st, Caddy: caddy, SecureCookies: *secureCookies,
			Apply: applier, CaddyDataDir: envOr("CPM_CADDY_DATA_DIR", "/caddy-data"), Box: box,
			Monitor: mon, DataDir: *dataDir, Restart: stop, GeoIP: geo, Hits: hitsDB, Bans: scorer,
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

// swapInRestore replaces the database with a staged backup (uploaded on
// the health page), keeping the old one as cpm.db.before-restore-<time>.
func swapInRestore(dataDir, dbPath string, log *slog.Logger) (bool, error) {
	staged := filepath.Join(dataDir, server.RestoreFile)
	if _, err := os.Stat(staged); err != nil {
		return false, nil
	}
	if _, err := os.Stat(dbPath); err == nil {
		old := dbPath + ".before-restore-" + time.Now().UTC().Format("20060102-150405")
		if err := os.Rename(dbPath, old); err != nil {
			return false, err
		}
		for _, ext := range []string{"-wal", "-shm"} {
			_ = os.Rename(dbPath+ext, old+ext)
		}
		log.Warn("restoring backup; previous database kept", "previous", old)
	}
	return true, os.Rename(staged, dbPath)
}

// noCaddy stands in when no admin socket is configured (e.g. `make run`
// during UI work): hosts can be edited, but applying fails clearly.
type noCaddy struct{}

var errNoCaddy = errors.New("no Caddy admin socket configured (set CPM_CADDY_ADMIN_SOCKET)")

func (noCaddy) Config(context.Context) ([]byte, error) { return nil, errNoCaddy }
func (noCaddy) Load(context.Context, []byte) error     { return errNoCaddy }

// splitList splits a comma-separated setting, dropping empty items.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
