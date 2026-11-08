package hits

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/encondata/switchyard/internal/geoip"
	"github.com/encondata/switchyard/internal/geoip/geoiptest"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	d, err := Open(context.Background(), filepath.Join(t.TempDir(), "hits.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func line(ts time.Time, ip, host, uri string, status int, extra string) string {
	return fmt.Sprintf(`{"level":"info","ts":%f,"logger":"http.log.access.cpm_access","msg":"handled request",`+
		`"request":{"remote_ip":%q,"client_ip":%q,"proto":"HTTP/1.1","method":"GET","host":%q,"uri":%q,`+
		`"headers":{"User-Agent":["curl/8"]}},"bytes_read":0,"duration":0.0123,"size":512,"status":%d%s}`+"\n",
		float64(ts.UnixNano())/1e9, ip, ip, host, uri, status, extra)
}

func TestParseLine(t *testing.T) {
	now := time.Now()
	h, ok := ParseLine([]byte(line(now, "203.0.113.9", "App.Example.com:443", "/a/b?token=secret", 403, `,"cpm_blocked":"deny:policy:3"`)), nil)
	if !ok || h.Host != "app.example.com" || h.Path != "/a/b" || h.Matched != "blocked" || h.Reason != "deny:policy:3" ||
		h.UserAgent != "curl/8" || h.DurationMS < 12 || h.DurationMS > 13 {
		t.Fatalf("hit = %+v", h)
	}
	if _, ok := ParseLine([]byte(`{"level":"error","msg":"x"}`), nil); ok {
		t.Fatal("non-access line accepted")
	}
}

func TestIngestAndStats(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	geoPath := filepath.Join(dir, "geo.mmdb")
	if err := geoiptest.Write(geoPath, map[string]string{"203.0.113.0/24": "AU"}); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "access.log")
	d := openTest(t)
	var seen int
	in := &Ingester{DB: d, File: log, Geo: &geoip.DB{Path: geoPath}, Log: slog.Default(),
		OnHits: func(_ context.Context, b []Hit) { seen += len(b) }}

	// No file yet: nothing to do.
	if err := in.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	write := func(s string) {
		f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(s)
		_ = f.Close()
	}
	write(line(now, "203.0.113.9", "a.example.com", "/", 200, "") +
		line(now, "203.0.113.9", "a.example.com", "/x", 500, "") +
		line(now, "198.51.100.1", "b.example.com", "/", 403, `,"cpm_blocked":"not_allowed"`) +
		`{"partial":`) // Caddy mid-write
	if err := in.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if seen != 3 {
		t.Fatalf("seen %d hits, want 3 (partial line held back)", seen)
	}
	write(`"rest"}` + "\n" + line(now, "203.0.113.10", "a.example.com", "/", 200, ""))
	if err := in.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if seen != 4 {
		t.Fatalf("seen %d hits after the rest arrived, want 4", seen)
	}

	// Rotation: the old file is renamed, a new one appears.
	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	write(line(now, "203.0.113.11", "b.example.com", "/new", 200, ""))
	if err := in.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if seen != 5 {
		t.Fatalf("seen %d hits after rotation, want 5", seen)
	}

	// A restarted ingester resumes where it left off.
	in2 := &Ingester{DB: d, File: log, Log: slog.Default(), OnHits: func(_ context.Context, b []Hit) { seen += len(b) }}
	if err := in2.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if seen != 5 {
		t.Fatalf("restart re-read lines: seen %d", seen)
	}

	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	o, err := d.Overview(ctx, from, to, nil)
	if err != nil || o.Requests != 5 || o.Errors != 1 || o.Blocked != 1 || o.Bytes != 5*512 {
		t.Fatalf("overview = %+v, %v", o, err)
	}
	if o, _ := d.Overview(ctx, from, to, []string{"b.example.com"}); o.Requests != 2 {
		t.Fatalf("filtered overview = %d", o.Requests)
	}
	ips, _ := d.Top(ctx, DimIP, from, to, nil, 10)
	if len(ips) != 4 || ips[0].Key != "203.0.113.9" || ips[0].Count != 2 || ips[0].Country != "AU" {
		t.Fatalf("top ips = %+v", ips)
	}
	countries, _ := d.Top(ctx, DimCountry, from, to, nil, 10)
	if len(countries) == 0 || countries[0].Key != "AU" || countries[0].Count != 4 {
		t.Fatalf("top countries = %+v", countries)
	}
	statuses, _ := d.Top(ctx, DimStatus, from, to, nil, 10)
	if statuses[0].Key != "2xx" {
		t.Fatalf("top statuses = %+v", statuses)
	}
	lat, _ := d.Latency(ctx, from, to, nil)
	if lat.Samples != 4 || lat.P50 < 12 {
		t.Fatalf("latency = %+v", lat)
	}
	tail, _ := d.Tail(ctx, 0, nil, 2)
	if len(tail) != 2 || tail[1].Path != "/new" {
		t.Fatalf("tail = %+v", tail)
	}
	hist, _ := d.IP(ctx, "198.51.100.1", from)
	if hist.Total != 1 || hist.Blocked != 1 || len(hist.Recent) != 1 {
		t.Fatalf("ip history = %+v", hist)
	}

	// Retention: everything is older than a 1ns window.
	n, err := d.Prune(ctx, now.Add(48*time.Hour), time.Nanosecond, time.Nanosecond)
	if err != nil || n != 5 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	if o, _ := d.Overview(ctx, from, to, nil); o.Requests != 0 {
		t.Fatal("rollups not pruned")
	}
}
