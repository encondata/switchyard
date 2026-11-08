package hits

import (
	"context"
	"testing"
	"time"
)

func TestCountryDetail(t *testing.T) {
	ctx := context.Background()
	d := openTest(t)
	now := time.Now().UTC()
	h := func(ip, country, host, path string, status int, matched string) Hit {
		return Hit{TS: now.Add(-time.Minute), Host: host, ClientIP: ip, Country: country, Method: "GET", Path: path,
			Status: status, Bytes: 100, Matched: matched}
	}
	if err := d.Insert(ctx, []Hit{
		h("203.0.113.9", "AU", "a.example.com", "/login", 200, "allowed"),
		h("203.0.113.9", "AU", "a.example.com", "/login", 200, "allowed"),
		h("203.0.113.9", "AU", "a.example.com", "/wp-admin", 403, "blocked"),
		h("203.0.113.10", "AU", "b.example.com", "/", 502, "allowed"),
		h("198.51.100.1", "DE", "a.example.com", "/", 200, "allowed"),
	}); err != nil {
		t.Fatal(err)
	}
	from, to := now.Add(-24*time.Hour), now.Add(time.Minute)
	c, err := d.Country(ctx, "AU", from, to, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if c.Requests != 4 || c.Blocked != 1 || c.Errors != 1 || c.Bytes != 400 || c.UniqueIPs != 2 {
		t.Errorf("totals = requests %d blocked %d errors %d bytes %d ips %d", c.Requests, c.Blocked, c.Errors, c.Bytes, c.UniqueIPs)
	}
	if len(c.Hosts) != 2 || c.Hosts[0].Key != "a.example.com" || c.Hosts[0].Count != 3 || c.Hosts[0].Blocked != 1 {
		t.Errorf("hosts = %+v", c.Hosts)
	}
	if len(c.Paths) != 3 || c.Paths[0].Key != "/login" || c.Paths[0].Count != 2 {
		t.Errorf("paths = %+v", c.Paths)
	}
	if len(c.IPs) != 2 || c.IPs[0].Key != "203.0.113.9" || c.IPs[0].Count != 3 {
		t.Errorf("ips = %+v", c.IPs)
	}
	status := map[string]int64{}
	for _, s := range c.Status {
		status[s.Key] = s.Count
	}
	if status["2xx"] != 2 || status["4xx"] != 1 || status["5xx"] != 1 {
		t.Errorf("status = %+v", c.Status)
	}
	if len(c.Recent) != 4 {
		t.Errorf("recent = %d", len(c.Recent))
	}
	for _, r := range c.Recent {
		if r.Country != "AU" {
			t.Errorf("recent has %s", r.Country)
		}
	}
	if len(c.Series) == 0 {
		t.Error("no series")
	}

	// Host filter.
	c, err = d.Country(ctx, "AU", from, to, []string{"b.example.com"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if c.Requests != 1 || len(c.Hosts) != 1 || len(c.Paths) != 1 || len(c.Recent) != 1 || c.UniqueIPs != 1 {
		t.Errorf("filtered = requests %d hosts %v paths %v recent %d ips %d", c.Requests, c.Hosts, c.Paths, len(c.Recent), c.UniqueIPs)
	}

	// A country with no traffic: empty, not nil, lists.
	c, err = d.Country(ctx, "FR", from, to, nil, 10)
	if err != nil || c.Requests != 0 || c.Hosts == nil || c.Paths == nil || c.Recent == nil {
		t.Errorf("empty country = %+v, %v", c, err)
	}
}
