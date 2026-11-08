package honeypot

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/encondata/switchyard/internal/hits"
	"github.com/encondata/switchyard/internal/store"
)

func TestAbuseBans(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	settings, _ := st.Honeypot(ctx)
	if settings.Enabled || !settings.Abuse.Enabled {
		t.Fatalf("defaults: honeypot %v, abuse %v (abuse should work with the honeypot off)", settings.Enabled, settings.Abuse.Enabled)
	}
	settings.Abuse = store.AbuseSettings{Enabled: true, WindowMinutes: 5, RateLimited: 10, Blocked: 10, NotFound: 20}
	if _, err := st.SaveHoneypot(ctx, settings, "admin"); err != nil {
		t.Fatal(err)
	}
	p := &pusher{}
	changed := 0
	sc := &Scorer{Store: st, Pusher: p, Log: slog.Default(), OnChange: func() { changed++ }}
	now := time.Now().UTC()
	burst := func(ip string, n, status int, matched, reason string, spacing time.Duration) []hits.Hit {
		var out []hits.Hit
		for i := 0; i < n; i++ {
			out = append(out, hits.Hit{TS: now.Add(time.Duration(i) * spacing), ClientIP: ip, Host: "a.example.com",
				Method: "GET", Path: "/x", Status: status, Matched: matched, Reason: reason})
		}
		return out
	}
	banned := func(ip string) bool { b, _ := st.IsBanned(ctx, ip); return b }

	// Just under the threshold: no ban.
	sc.HandleHits(ctx, burst("203.0.113.1", 9, 429, "allowed", "", time.Second))
	if banned("203.0.113.1") {
		t.Fatal("banned below the threshold")
	}
	// Reaching it: banned, the list pushed and OnChange called.
	sc.HandleHits(ctx, burst("203.0.113.1", 1, 429, "allowed", "", time.Second))
	if !banned("203.0.113.1") || p.n == 0 || changed == 0 {
		t.Fatalf("rate-limited flood: banned %v, pushes %d, changes %d", banned("203.0.113.1"), p.n, changed)
	}
	bans, _ := st.ListBans(ctx, true, 10)
	if len(bans) != 1 || bans[0].Source != "abuse" || !strings.Contains(bans[0].Reason, "10 rate-limited requests in 5 min") {
		t.Errorf("ban = %+v", bans)
	}

	// Blocked by access rules, and 404s.
	sc.HandleHits(ctx, burst("203.0.113.2", 10, 403, "blocked", "not_allowed", time.Second))
	sc.HandleHits(ctx, burst("203.0.113.3", 20, 404, "allowed", "", time.Second))
	if !banned("203.0.113.2") || !banned("203.0.113.3") {
		t.Errorf("blocked %v, not found %v", banned("203.0.113.2"), banned("203.0.113.3"))
	}

	// Spread out past the window: never reaches the count.
	sc.HandleHits(ctx, burst("203.0.113.4", 30, 429, "allowed", "", time.Minute))
	if banned("203.0.113.4") {
		t.Error("banned for events spread over 30 minutes")
	}
	// Normal answers, already-banned and honeypot hits don't count.
	sc.HandleHits(ctx, burst("203.0.113.5", 50, 200, "allowed", "", time.Second))
	sc.HandleHits(ctx, burst("203.0.113.6", 50, 403, "blocked", "banned", time.Second))
	sc.HandleHits(ctx, burst("203.0.113.7", 50, 404, "honeypot", "catchall", time.Second))
	for _, ip := range []string{"203.0.113.5", "203.0.113.6", "203.0.113.7"} {
		if banned(ip) {
			t.Errorf("%s banned", ip)
		}
	}
	// Local network and never-block addresses are never banned.
	if _, err := st.AddNeverBan(ctx, "198.51.100.0/24", "office", "admin"); err != nil {
		t.Fatal(err)
	}
	sc.HandleHits(ctx, burst("192.168.1.20", 50, 429, "allowed", "", time.Second))
	sc.HandleHits(ctx, burst("198.51.100.9", 50, 429, "allowed", "", time.Second))
	if banned("192.168.1.20") || banned("198.51.100.9") {
		t.Error("banned a local or never-block address")
	}

	// A repeat offender's ban is longer.
	first := bans[0]
	if err := st.RemoveBan(ctx, first.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	sc.HandleHits(ctx, burst("203.0.113.1", 10, 429, "allowed", "", time.Second))
	again, _ := st.ListBans(ctx, true, 10)
	for _, b := range again {
		if b.CIDR == "203.0.113.1" && b.ExpiresAt != nil && first.ExpiresAt != nil &&
			b.ExpiresAt.Sub(b.CreatedAt) <= first.ExpiresAt.Sub(first.CreatedAt) {
			t.Errorf("repeat ban not longer: %v vs %v", b.ExpiresAt.Sub(b.CreatedAt), first.ExpiresAt.Sub(first.CreatedAt))
		}
	}

	// Turned off: nothing.
	settings.Abuse.Enabled = false
	_, _ = st.SaveHoneypot(ctx, settings, "admin")
	sc.HandleHits(ctx, burst("203.0.113.8", 50, 429, "allowed", "", time.Second))
	if banned("203.0.113.8") {
		t.Error("banned with abuse bans off")
	}
}

func TestAbuseValidation(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	s, _ := st.Honeypot(ctx)
	for _, a := range []store.AbuseSettings{
		{Enabled: true, WindowMinutes: 0, RateLimited: 30},
		{Enabled: true, WindowMinutes: 5, RateLimited: 2},
		{Enabled: true, WindowMinutes: 5},
	} {
		s.Abuse = a
		if _, err := st.SaveHoneypot(ctx, s, "admin"); err == nil {
			t.Errorf("accepted %+v", a)
		}
	}
}

type failingPusher struct{}

func (failingPusher) PushBans(context.Context) error { return errors.New("caddy unreachable") }

// The firewall sync must hear about new bans even while Caddy can't take
// them (down, restarting, or not configured yet).
func TestOnChangeDoesNotWaitForCaddy(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	changed := 0
	sc := &Scorer{Store: st, Pusher: failingPusher{}, Log: slog.Default(), OnChange: func() { changed++ }}
	var batch []hits.Hit
	for i := 0; i < 100; i++ {
		batch = append(batch, hits.Hit{TS: time.Now(), ClientIP: "203.0.113.50", Host: "a.example.com", Method: "GET", Path: "/", Status: 404, Matched: "allowed"})
	}
	sc.HandleHits(ctx, batch)
	if b, _ := st.IsBanned(ctx, "203.0.113.50"); !b || changed != 1 {
		t.Fatalf("banned %v, OnChange %d times; want banned, once", b, changed)
	}
	sc.Push(ctx) // same list again: no repeat
	if changed != 1 {
		t.Errorf("OnChange repeated for an unchanged list: %d", changed)
	}
	if err := sc.ForcePush(ctx); err == nil || changed != 1 {
		t.Errorf("ForcePush err %v, OnChange %d", err, changed)
	}
}
