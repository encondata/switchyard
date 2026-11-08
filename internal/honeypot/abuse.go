package honeypot

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/encondata/switchyard/internal/geoip"
	"github.com/encondata/switchyard/internal/hits"
	"github.com/encondata/switchyard/internal/store"
)

// What an abusive address keeps getting.
const (
	abuseRateLimited = iota
	abuseBlocked
	abuseNotFound
	abuseKinds
)

var abuseText = [abuseKinds]string{"rate-limited requests", "blocked requests", "not-found requests"}

// maxTracked bounds memory in a flood of distinct addresses; past it, new
// addresses aren't tracked until old ones age out.
const maxTracked = 100_000

// abuseTracker counts, per address, recent rate-limited, blocked and
// not-found answers. Only addresses that get such answers are tracked, and
// each keeps at most as many times as its threshold.
type abuseTracker struct {
	mu  sync.Mutex
	ips map[string]*abuseIP
}

type abuseIP struct {
	times [abuseKinds][]time.Time
	last  time.Time
}

func abuseKind(h hits.Hit) (int, bool) {
	switch {
	case h.Matched == "honeypot":
		return 0, false // the honeypot scores these
	case h.Matched == "blocked":
		if h.Reason == "banned" {
			return 0, false // already banned
		}
		return abuseBlocked, true
	case h.Status == 429:
		return abuseRateLimited, true
	case h.Status == 404:
		return abuseNotFound, true
	}
	return 0, false
}

// add records one event and returns how many of that kind the address has
// had within the window.
func (t *abuseTracker) add(ip string, kind int, at time.Time, window time.Duration, keep int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ips == nil {
		t.ips = map[string]*abuseIP{}
	}
	a := t.ips[ip]
	if a == nil {
		if len(t.ips) >= maxTracked {
			return 0
		}
		a = &abuseIP{}
		t.ips[ip] = a
	}
	ts := a.times[kind]
	cut := at.Add(-window)
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	ts = append(ts[i:], at)
	if len(ts) > keep {
		ts = ts[len(ts)-keep:]
	}
	a.times[kind] = ts
	if at.After(a.last) {
		a.last = at
	}
	return len(ts)
}

func (t *abuseTracker) forget(ip string) {
	t.mu.Lock()
	delete(t.ips, ip)
	t.mu.Unlock()
}

// prune drops addresses with nothing in the window.
func (t *abuseTracker) prune(now time.Time, window time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, a := range t.ips {
		if now.Sub(a.last) > window {
			delete(t.ips, ip)
		}
	}
}

// abuseBans counts this batch's abusive answers and bans addresses over a
// threshold. It returns how many it banned.
func (s *Scorer) abuseBans(ctx context.Context, batch []hits.Hit, settings store.HoneypotSettings) int {
	a := settings.Abuse
	window := time.Duration(a.WindowMinutes) * time.Minute
	limit := [abuseKinds]int{a.RateLimited, a.Blocked, a.NotFound}
	banned := 0
	for _, h := range batch {
		kind, ok := abuseKind(h)
		if !ok || h.ClientIP == "" || limit[kind] == 0 || geoip.IsLocal(h.ClientIP) {
			continue
		}
		n := s.abuse.add(h.ClientIP, kind, h.TS, window, limit[kind])
		if n < limit[kind] {
			continue
		}
		s.abuse.forget(h.ClientIP)
		if never, _ := s.Store.IsNeverBan(ctx, h.ClientIP); never {
			continue
		}
		if already, _ := s.Store.IsBanned(ctx, h.ClientIP); already {
			continue
		}
		past, _ := s.Store.PastBans(ctx, h.ClientIP)
		length := BanLength(settings, past)
		reason := fmt.Sprintf("Abuse: %d %s in %d min (last: %s %s%s)", n, abuseText[kind], a.WindowMinutes, h.Method, h.Host, h.Path)
		if _, err := s.Store.AddBan(ctx, h.ClientIP, reason, "abuse", length, n, "abuse"); err != nil {
			s.Log.Warn("abuse: banning", "ip", h.ClientIP, "err", err)
			continue
		}
		s.Log.Warn("abuse: banned", "ip", h.ClientIP, "why", abuseText[kind], "count", n, "for", length.String(), "repeat", past)
		banned++
	}
	return banned
}
