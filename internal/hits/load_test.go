package hits

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestLoad fills the database with CPM_LOADTEST hits spread over 45 days
// (spec §8: 45 days at ~1M/day) and times the dashboard queries.
// Run: CPM_LOADTEST=3000000 go test ./internal/hits -run TestLoad -v -timeout 30m
func TestLoad(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("CPM_LOADTEST"))
	if n == 0 {
		t.Skip("set CPM_LOADTEST to run the load test")
	}
	ctx := context.Background()
	dir := os.Getenv("CPM_LOADTEST_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	d, err := Open(ctx, filepath.Join(dir, "load.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()

	now := time.Now().UTC()
	start := now.Add(-45 * 24 * time.Hour)
	hostsList := []string{"app.example.com", "api.example.com", "www.example.com", "nas.lan.example.com", "git.example.com"}
	countries := []string{"US", "DE", "GB", "FR", "NL", "CN", "RU", "BR", "IN", ""}
	paths := []string{"/", "/api/v1/items", "/login", "/static/app.js", "/favicon.ico", "/.env", "/wp-login.php"}
	r := rand.New(rand.NewPCG(1, 2))
	batch := make([]Hit, 0, 1000)
	t0 := time.Now()
	for i := 0; i < n; i++ {
		ts := start.Add(time.Duration(float64(45*24*time.Hour) * float64(i) / float64(n)))
		status := 200
		if r.IntN(50) == 0 {
			status = 500
		} else if r.IntN(10) == 0 {
			status = 404
		}
		matched := "allowed"
		if r.IntN(20) == 0 {
			matched = "blocked"
		}
		batch = append(batch, Hit{
			TS: ts, Host: hostsList[r.IntN(len(hostsList))],
			ClientIP: fmt.Sprintf("10.%d.%d.%d", r.IntN(4), r.IntN(256), r.IntN(256)), Country: countries[r.IntN(len(countries))],
			Method: "GET", Path: paths[r.IntN(len(paths))], Status: status, Bytes: int64(r.IntN(50000)),
			DurationMS: r.Float64() * 200, UserAgent: "Mozilla/5.0", Matched: matched,
		})
		if len(batch) == cap(batch) {
			if err := d.Insert(ctx, batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	if err := d.Insert(ctx, batch); err != nil {
		t.Fatal(err)
	}
	took := time.Since(t0)
	t.Logf("inserted %d hits in %s (%.0f hits/s)", n, took.Round(time.Second), float64(n)/took.Seconds())

	timeIt := func(name string, fn func() error) {
		t0 := time.Now()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%-28s %s", name, time.Since(t0).Round(time.Millisecond))
	}
	for _, rng := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 45 * 24 * time.Hour} {
		from := now.Add(-rng)
		label := rng.String()
		timeIt("overview "+label, func() error { _, err := d.Overview(ctx, from, now, nil); return err })
		timeIt("top ips "+label, func() error { _, err := d.Top(ctx, DimIP, from, now, nil, 20); return err })
		timeIt("top paths "+label, func() error { _, err := d.Top(ctx, DimPath, from, now, nil, 20); return err })
		timeIt("top countries "+label, func() error { _, err := d.Top(ctx, DimCountry, from, now, nil, 20); return err })
		timeIt("latency "+label, func() error { _, err := d.Latency(ctx, from, now, nil); return err })
		timeIt("one host overview "+label, func() error {
			_, err := d.Overview(ctx, from, now, []string{"app.example.com"})
			return err
		})
	}
	timeIt("tail", func() error { _, err := d.Tail(ctx, int64(n-500), nil, 100); return err })
	timeIt("ip history", func() error { _, err := d.IP(ctx, "10.1.2.3", start); return err })
	timeIt("prune (nothing old)", func() error { _, err := d.Prune(ctx, now, DefaultRetainHits, DefaultRetainRollups); return err })
	if info, err := os.Stat(filepath.Join(dir, "load.db")); err == nil {
		t.Logf("database size: %d MB", info.Size()>>20)
	}
}
