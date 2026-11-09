// Package honeypot scores requests that hit the honeypot (the catch-all
// host and trap paths) and bans addresses that cross the threshold
// (spec F6, CPM-30).
package honeypot

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/encondata/switchyard/internal/hits"
	"github.com/encondata/switchyard/internal/store"
)

// BanPusher sends the current ban list to Caddy.
type BanPusher interface {
	PushBans(ctx context.Context) error
}

// Scorer turns honeypot hits into points and bans.
type Scorer struct {
	Store  *store.Store
	Pusher BanPusher
	Log    *slog.Logger

	// OnChange, if set, runs when the ban list changes (to sync it
	// elsewhere, e.g. a UniFi firewall). It doesn't wait for Caddy: the
	// firewall gets bans even while Caddy is unreachable.
	OnChange func()

	mu           sync.Mutex
	lastBans     string
	lastNotified string
	abuse        abuseTracker
}

// BanRetention is how long ended bans are kept (they hold IPs; decided
// 07 Nov 2026: 45 days after the ban ends).
const BanRetention = 45 * 24 * time.Hour

// globToRegexp turns a Caddy path pattern (* = any characters) into a
// regexp.
func globToRegexp(p string) *regexp.Regexp {
	parts := strings.Split(p, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
}

// Score returns the points for one honeypot hit. Trap hits carry the score
// of the trap Caddy matched ("trap:<score>").
func Score(h hits.Hit, settings store.HoneypotSettings, traps []store.TrapPath) int {
	if h.Reason == "catchall" || h.Reason == "hold" {
		// "hold": a host still behind its decoy, which only scanners (who
		// found its new certificate in the CT logs) know about yet.
		return settings.CatchallScore
	}
	if v, ok := strings.CutPrefix(h.Reason, "trap:"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return min(n, 1000)
		}
	}
	// Older log lines tagged just "trap": match the path the way Caddy does
	// (case-insensitively).
	best := 0
	for _, t := range traps {
		if t.Enabled && t.Score > best && globToRegexp(strings.ToLower(t.Pattern)).MatchString(strings.ToLower(h.Path)) {
			best = t.Score
		}
	}
	return best
}

// BanLength doubles for each earlier honeypot ban, up to the maximum.
func BanLength(settings store.HoneypotSettings, pastBans int) time.Duration {
	days := settings.BanDays
	for i := 0; i < pastBans && days < settings.MaxBanDays; i++ {
		days *= 2
	}
	if days > settings.MaxBanDays {
		days = settings.MaxBanDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// HandleHits is the ingester's OnHits callback.
func (s *Scorer) HandleHits(ctx context.Context, batch []hits.Hit) {
	settings, err := s.Store.Honeypot(ctx)
	if err != nil {
		return
	}
	banned := 0
	if settings.Enabled {
		banned += s.honeypotBans(ctx, batch, settings)
	}
	if settings.Abuse.Enabled {
		banned += s.abuseBans(ctx, batch, settings)
	}
	if banned > 0 {
		s.Push(ctx)
	}
}

// honeypotBans scores honeypot hits and bans addresses over the threshold.
func (s *Scorer) honeypotBans(ctx context.Context, batch []hits.Hit, settings store.HoneypotSettings) int {
	var traps []store.TrapPath
	var err error
	window := time.Duration(settings.WindowHours) * time.Hour
	banned := 0
	for _, h := range batch {
		if h.Matched != "honeypot" || h.ClientIP == "" {
			continue
		}
		if traps == nil {
			if traps, err = s.Store.ListTrapPaths(ctx); err != nil {
				s.Log.Warn("honeypot: loading traps", "err", err)
				return banned
			}
		}
		pts := Score(h, settings, traps)
		total, err := s.Store.AddPoints(ctx, h.ClientIP, h.TS, pts, window)
		if err != nil {
			s.Log.Warn("honeypot: recording points", "err", err)
			continue
		}
		if total < settings.Threshold {
			continue
		}
		if never, _ := s.Store.IsNeverBan(ctx, h.ClientIP); never {
			continue
		}
		if already, _ := s.Store.IsBanned(ctx, h.ClientIP); already {
			continue
		}
		past, _ := s.Store.PastBans(ctx, h.ClientIP)
		length := BanLength(settings, past)
		reason := fmt.Sprintf("Honeypot: %d points in %dh (last: %s %s%s)", total, settings.WindowHours, h.Method, h.Host, h.Path)
		if _, err := s.Store.AddBan(ctx, h.ClientIP, reason, "honeypot", length, total, "honeypot"); err != nil {
			s.Log.Warn("honeypot: banning", "ip", h.ClientIP, "err", err)
			continue
		}
		_ = s.Store.ClearPoints(ctx, h.ClientIP)
		s.Log.Warn("honeypot: banned", "ip", h.ClientIP, "points", total, "for", length.String(), "repeat", past)
		banned++
	}
	return banned
}

// Push sends the ban list to Caddy if it changed since the last push.
func (s *Scorer) Push(ctx context.Context) {
	bans, err := s.Store.ActiveBanRanges(ctx)
	if err != nil {
		return
	}
	key := strings.Join(bans, ",")
	s.notify(key)
	s.mu.Lock()
	same := key == s.lastBans
	s.mu.Unlock()
	if same {
		return
	}
	if err := s.Pusher.PushBans(ctx); err != nil {
		s.Log.Warn("honeypot: pushing bans to Caddy", "err", err)
		return
	}
	s.mu.Lock()
	s.lastBans = key
	s.mu.Unlock()
}

// notify calls OnChange if the ban list differs from the last one it saw.
func (s *Scorer) notify(key string) {
	if s.OnChange == nil {
		return
	}
	s.mu.Lock()
	changed := key != s.lastNotified
	s.lastNotified = key
	s.mu.Unlock()
	if changed {
		s.OnChange()
	}
}

// ForcePush sends the ban list now (after a manual ban or unban).
func (s *Scorer) ForcePush(ctx context.Context) error {
	s.mu.Lock()
	s.lastBans = "\x00"
	s.mu.Unlock()
	bans, _ := s.Store.ActiveBanRanges(ctx)
	s.notify(strings.Join(bans, ","))
	if err := s.Pusher.PushBans(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.lastBans = strings.Join(bans, ",")
	s.mu.Unlock()
	return nil
}

// Maintain runs every minute: pushes the ban list when bans expire, and
// prunes old points and ended bans.
func (s *Scorer) Maintain(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		s.Push(ctx)
		settings, _ := s.Store.Honeypot(ctx)
		s.abuse.prune(time.Now(), time.Duration(settings.Abuse.WindowMinutes)*time.Minute)
		window := time.Duration(settings.WindowHours) * time.Hour
		if err := s.Store.PruneHoneypot(ctx, time.Now().UTC(), window, BanRetention); err != nil && ctx.Err() == nil {
			s.Log.Warn("honeypot: pruning", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
