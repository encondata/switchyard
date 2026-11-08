package honeypot

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/encondata/switchyard/internal/hits"
	"github.com/encondata/switchyard/internal/store"
)

type pusher struct{ n int }

func (p *pusher) PushBans(context.Context) error { p.n++; return nil }

func TestScoreAndBanLength(t *testing.T) {
	s := store.DefaultHoneypot
	traps := []store.TrapPath{{Pattern: "/.git/*", Score: 10, Enabled: true}, {Pattern: "/.env", Score: 5, Enabled: true}, {Pattern: "/x", Score: 99}}
	cases := map[string]int{"/.git/config": 10, "/.env": 5, "/.envx": 0, "/x": 0}
	for path, want := range cases {
		if got := Score(hits.Hit{Path: path, Reason: "trap"}, s, traps); got != want {
			t.Errorf("Score(%s) = %d, want %d", path, got, want)
		}
	}
	if Score(hits.Hit{Path: "/.ENV", Reason: "trap:5"}, s, traps) != 5 {
		t.Error("tagged trap score should be used as-is (Caddy matched /.ENV)")
	}
	if Score(hits.Hit{Path: "/.GIT/config", Reason: "trap"}, s, traps) != 10 {
		t.Error("legacy trap tag should match case-insensitively")
	}
	if Score(hits.Hit{Reason: "catchall"}, s, traps) != 1 {
		t.Error("catch-all score")
	}
	for past, want := range map[int]int{0: 7, 1: 14, 2: 28, 3: 56, 4: 90, 9: 90} {
		if got := BanLength(s, past); got != time.Duration(want)*24*time.Hour {
			t.Errorf("BanLength(%d) = %s, want %dd", past, got, want)
		}
	}
}

func TestAutoBan(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	settings := store.DefaultHoneypot
	settings.Enabled = true
	if _, err := st.SaveHoneypot(ctx, settings, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddNeverBan(ctx, "192.168.1.0/24", "office", "admin"); err != nil {
		t.Fatal(err)
	}
	p := &pusher{}
	sc := &Scorer{Store: st, Pusher: p, Log: slog.Default()}
	now := time.Now()
	hit := func(ip, path, reason string) hits.Hit {
		return hits.Hit{TS: now, ClientIP: ip, Host: "x", Method: "GET", Path: path, Matched: "honeypot", Reason: reason}
	}

	// Nine catch-all hits: 9 points, below the threshold of 10.
	var batch []hits.Hit
	for i := 0; i < 9; i++ {
		batch = append(batch, hit("203.0.113.5", "/", "catchall"))
	}
	sc.HandleHits(ctx, batch)
	if b, _ := st.IsBanned(ctx, "203.0.113.5"); b || p.n != 0 {
		t.Fatal("banned below the threshold")
	}
	// One more: banned, and the list is pushed.
	sc.HandleHits(ctx, []hits.Hit{hit("203.0.113.5", "/", "catchall")})
	if b, _ := st.IsBanned(ctx, "203.0.113.5"); !b || p.n != 1 {
		t.Fatalf("not banned at the threshold (pushes %d)", p.n)
	}
	// A trap path is worth 10: one hit bans.
	sc.HandleHits(ctx, []hits.Hit{hit("198.51.100.9", "/.env", "trap:10")})
	if b, _ := st.IsBanned(ctx, "198.51.100.9"); !b {
		t.Fatal("trap hit didn't ban")
	}
	// Never-block addresses are never banned.
	sc.HandleHits(ctx, []hits.Hit{hit("192.168.1.20", "/.env", "trap:10"), hit("192.168.1.20", "/.git/config", "trap:10")})
	if b, _ := st.IsBanned(ctx, "192.168.1.20"); b {
		t.Fatal("never-block address banned")
	}
	// Repeat offender: second ban is twice as long.
	bans, _ := st.ListBans(ctx, true, 10)
	var first store.Ban
	for _, b := range bans {
		if b.CIDR == "198.51.100.9" {
			first = b
		}
	}
	if err := st.RemoveBan(ctx, first.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	sc.HandleHits(ctx, []hits.Hit{hit("198.51.100.9", "/.env", "trap:10")})
	bans, _ = st.ListBans(ctx, true, 10)
	for _, b := range bans {
		if b.CIDR == "198.51.100.9" {
			days := b.ExpiresAt.Sub(b.CreatedAt).Hours() / 24
			if days < 13.9 || days > 14.1 {
				t.Fatalf("repeat ban = %.1f days, want 14", days)
			}
		}
	}

	// Disabled honeypot: nothing happens.
	settings.Enabled = false
	_, _ = st.SaveHoneypot(ctx, settings, "admin")
	sc.HandleHits(ctx, []hits.Hit{hit("203.0.113.77", "/.env", "trap:10")})
	if b, _ := st.IsBanned(ctx, "203.0.113.77"); b {
		t.Fatal("banned while the honeypot is off")
	}
}
