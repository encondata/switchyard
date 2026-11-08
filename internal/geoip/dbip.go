package geoip

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DBIPFile is the name the DB-IP database is saved under.
const DBIPFile = "dbip-country-lite.mmdb"

// Updater keeps DB-IP's free IP-to-Country Lite database (CC BY 4.0,
// https://db-ip.com) in Dir, so countries work without a MaxMind account.
// DB-IP publishes it monthly. When a MaxMind GeoLite2 file (MaxMindPath)
// is installed, that is used instead and nothing is downloaded.
type Updater struct {
	Dir         string
	MaxMindPath string
	Log         *slog.Logger
	// OnUpdate runs after a new database is in place.
	OnUpdate func()

	// For tests.
	BaseURL string
	Client  *http.Client
	Now     func() time.Time
}

const (
	dbipBase = "https://download.db-ip.com/free"
	// Refresh once the file is a month old; DB-IP updates monthly.
	dbipMaxAge = 30 * 24 * time.Hour
	// The unpacked database is about 8 MB; anything far larger is wrong.
	dbipMaxSize = 200 << 20
)

var errNotPublished = errors.New("not published")

// Path is where the DB-IP database is kept.
func (u *Updater) Path() string { return filepath.Join(u.Dir, DBIPFile) }

// Run updates now, then checks every few hours until ctx ends.
func (u *Updater) Run(ctx context.Context) {
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		if updated, err := u.Update(ctx); err != nil {
			u.log().Warn("country database: download failed; will retry", "err", err)
		} else if updated && u.OnUpdate != nil {
			u.OnUpdate()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Update downloads the database if it's missing or a month old. It
// reports whether a new file was put in place.
func (u *Updater) Update(ctx context.Context) (bool, error) {
	if u.MaxMindPath != "" {
		if _, err := os.Stat(u.MaxMindPath); err == nil {
			return false, nil // MaxMind is installed and preferred
		}
	}
	now := u.now()
	if info, err := os.Stat(u.Path()); err == nil && now.Sub(info.ModTime()) < dbipMaxAge {
		return false, nil
	}
	// This month's file, or last month's early in a month before it's out.
	var lastErr error
	for _, m := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := fmt.Sprintf("%s/dbip-country-lite-%s.mmdb.gz", u.base(), m.UTC().Format("2006-01"))
		err := u.fetch(ctx, url)
		if err == nil {
			u.log().Info("country database updated", "source", "DB-IP", "month", m.UTC().Format("2006-01"))
			return true, nil
		}
		lastErr = err
		if !errors.Is(err, errNotPublished) {
			break
		}
	}
	return false, lastErr
}

func (u *Updater) fetch(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Switchyard (+https://github.com/encondata/switchyard)")
	resp, err := u.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return errNotPublished
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s answered %s", url, resp.Status)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("unpacking %s: %w", url, err)
	}
	if err := os.MkdirAll(u.Dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(u.Dir, ".dbip-*.mmdb")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	n, err := io.Copy(tmp, io.LimitReader(zr, dbipMaxSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("unpacking %s: %w", url, err)
	}
	if n > dbipMaxSize {
		return fmt.Errorf("%s is larger than expected", url)
	}
	if err := checkDB(tmp.Name()); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	// Caddy reads it too (as uid 1000), so it must be world-readable.
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), u.Path())
}

// checkDB makes sure a download is a country database that places a
// well-known address, before it replaces a working one.
func checkDB(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("not a usable database: %w", err)
	}
	defer func() { _ = r.Close() }()
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.Lookup(netip.MustParseAddr("8.8.8.8")).Decode(&rec); err != nil || rec.Country.ISOCode == "" {
		return errors.New("the database has no country for 8.8.8.8")
	}
	return nil
}

func (u *Updater) base() string {
	if u.BaseURL != "" {
		return u.BaseURL
	}
	return dbipBase
}

func (u *Updater) client() *http.Client {
	if u.Client != nil {
		return u.Client
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) log() *slog.Logger {
	if u.Log != nil {
		return u.Log
	}
	return slog.Default()
}
