package geoip_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/encondata/switchyard/internal/geoip"
	"github.com/encondata/switchyard/internal/geoip/geoiptest"
)

// dbipServer serves gzipped DB-IP-style databases for the given months.
func dbipServer(t *testing.T, months ...string) (*httptest.Server, *int) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src.mmdb")
	if err := geoiptest.WriteType(src, "DBIP-Country-Lite", map[string]string{"8.8.8.0/24": "US", "81.2.69.0/24": "GB"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(src)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		for _, m := range months {
			if r.URL.Path == "/dbip-country-lite-"+m+".mmdb.gz" {
				_, _ = w.Write(gz.Bytes())
				return
			}
		}
		if strings.Contains(r.URL.Path, "garbage") {
			_, _ = w.Write([]byte("not gzip"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

func TestUpdaterDownloadsAndDBUsesIt(t *testing.T) {
	ts, calls := dbipServer(t, "2026-11")
	dir := t.TempDir()
	u := &geoip.Updater{Dir: dir, MaxMindPath: filepath.Join(dir, "GeoLite2-Country.mmdb"), BaseURL: ts.URL,
		Now: func() time.Time { return time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC) }}
	db := &geoip.DB{Path: u.MaxMindPath, Fallback: u.Path()}
	if db.Available() || db.Locate("8.8.8.8") != "" {
		t.Fatal("database available before download")
	}
	updated, err := u.Update(context.Background())
	if err != nil || !updated {
		t.Fatalf("Update = %v, %v", updated, err)
	}
	if got := db.Country("8.8.8.8"); got != "US" {
		t.Errorf("Country(8.8.8.8) = %q", got)
	}
	if got := db.Source(); got != "DB-IP" {
		t.Errorf("Source = %q", got)
	}
	if db.ActivePath() != u.Path() {
		t.Errorf("ActivePath = %q", db.ActivePath())
	}
	info, _ := os.Stat(u.Path())
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want world-readable for Caddy", info.Mode())
	}
	// Fresh: no second download.
	before := *calls
	if updated, err := u.Update(context.Background()); err != nil || updated || *calls != before {
		t.Errorf("second Update = %v, %v (calls %d -> %d)", updated, err, before, *calls)
	}
}

func TestUpdaterFallsBackToLastMonth(t *testing.T) {
	ts, _ := dbipServer(t, "2026-10") // November's isn't out yet
	dir := t.TempDir()
	u := &geoip.Updater{Dir: dir, BaseURL: ts.URL, Now: func() time.Time { return time.Date(2026, 11, 1, 1, 0, 0, 0, time.UTC) }}
	if updated, err := u.Update(context.Background()); err != nil || !updated {
		t.Fatalf("Update = %v, %v", updated, err)
	}
}

func TestUpdaterSkipsWhenMaxMindInstalled(t *testing.T) {
	ts, calls := dbipServer(t, "2026-11")
	dir := t.TempDir()
	mm := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if err := geoiptest.Write(mm, map[string]string{"8.8.8.0/24": "US"}); err != nil {
		t.Fatal(err)
	}
	u := &geoip.Updater{Dir: dir, MaxMindPath: mm, BaseURL: ts.URL}
	if updated, err := u.Update(context.Background()); err != nil || updated || *calls != 0 {
		t.Fatalf("Update = %v, %v, calls %d", updated, err, *calls)
	}
	db := &geoip.DB{Path: mm, Fallback: u.Path()}
	if db.Source() != "MaxMind" {
		t.Errorf("Source = %q", db.Source())
	}
}

func TestUpdaterKeepsWorkingFileOnBadDownload(t *testing.T) {
	ts, _ := dbipServer(t) // nothing published
	dir := t.TempDir()
	u := &geoip.Updater{Dir: dir, BaseURL: ts.URL + "/garbage", Now: func() time.Time { return time.Now() }}
	old := u.Path()
	if err := geoiptest.WriteType(old, "DBIP-Country-Lite", map[string]string{"8.8.8.0/24": "US"}); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-40 * 24 * time.Hour)
	_ = os.Chtimes(old, stale, stale)
	if _, err := u.Update(context.Background()); err == nil {
		t.Fatal("bad download accepted")
	}
	db := &geoip.DB{Fallback: old}
	if db.Country("8.8.8.8") != "US" {
		t.Error("working database was replaced by a bad download")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("leftover files: %v", entries)
	}
}

func TestLocateLocalNetwork(t *testing.T) {
	db := &geoip.DB{}
	for _, ip := range []string{"192.168.1.5", "10.0.0.1", "172.20.0.1", "127.0.0.1", "100.64.1.1", "fd00::1", "::ffff:192.168.0.9"} {
		if got := db.Locate(ip); got != geoip.LocalNetwork {
			t.Errorf("Locate(%s) = %q, want %q", ip, got, geoip.LocalNetwork)
		}
	}
	if got := db.Locate("8.8.8.8"); got != "" {
		t.Errorf("Locate(8.8.8.8) with no database = %q", got)
	}
}
