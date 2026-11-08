package hits

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/encondata/switchyard/internal/geoip"
	"github.com/encondata/switchyard/internal/geoip/geoiptest"
)

func TestFillCountries(t *testing.T) {
	ctx := context.Background()
	d := openTest(t)
	now := time.Now().UTC().Truncate(time.Hour).Add(10 * time.Minute)
	// Logged before any country database existed.
	hit := func(ip, host string, status int, matched string, ago time.Duration) Hit {
		return Hit{TS: now.Add(-ago), Host: host, ClientIP: ip, Method: "GET", Path: "/", Status: status, Bytes: 100, Matched: matched}
	}
	if err := d.Insert(ctx, []Hit{
		hit("203.0.113.9", "a.example.com", 200, "allowed", 0),
		hit("203.0.113.9", "a.example.com", 200, "allowed", 0),
		hit("203.0.113.9", "a.example.com", 403, "blocked", 2*time.Hour),
		hit("198.51.100.1", "b.example.com", 200, "allowed", 0),
		hit("192.168.1.20", "a.example.com", 200, "allowed", 0),
		hit("192.0.2.77", "a.example.com", 200, "allowed", 0), // not in the database
	}); err != nil {
		t.Fatal(err)
	}
	from, to := now.Add(-24*time.Hour), now.Add(time.Hour)
	before, _ := d.Overview(ctx, from, to, nil)

	geoPath := filepath.Join(t.TempDir(), "geo.mmdb")
	if err := geoiptest.Write(geoPath, map[string]string{"203.0.113.0/24": "AU", "198.51.100.0/24": "DE"}); err != nil {
		t.Fatal(err)
	}
	geo := &geoip.DB{Path: geoPath}
	n, err := d.FillCountries(ctx, geo.Locate)
	if err != nil || n != 5 {
		t.Fatalf("FillCountries = %d, %v; want 5", n, err)
	}

	got := map[string]int64{}
	rows, err := d.Top(ctx, "country", from, to, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		got[r.Key] = r.Count
	}
	want := map[string]int64{"AU": 3, "DE": 1, geoip.LocalNetwork: 1, "": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("country %q = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}
	after, _ := d.Overview(ctx, from, to, nil)
	if after.Requests != before.Requests || after.Blocked != before.Blocked || after.Bytes != before.Bytes {
		t.Errorf("totals changed: before %+v, after %+v", before, after)
	}
	var ipCountry string
	_ = d.db.QueryRowContext(ctx, `SELECT country FROM ip_daily WHERE ip = '203.0.113.9' LIMIT 1`).Scan(&ipCountry)
	if ipCountry != "AU" {
		t.Errorf("ip_daily country = %q", ipCountry)
	}
	// Running again finds nothing new to fill.
	if n, err := d.FillCountries(ctx, geo.Locate); err != nil || n != 0 {
		t.Errorf("second FillCountries = %d, %v", n, err)
	}
}
