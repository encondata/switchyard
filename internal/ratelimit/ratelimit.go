// Package ratelimit counts failures per key (IP address, username) in a
// sliding window, to slow down password guessing.
package ratelimit

import (
	"hash/maphash"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMaxKeys bounds memory when many different keys (IPs, usernames)
// fail.
const DefaultMaxKeys = 100_000

// maxKeyLen bounds the memory one key can use.
const maxKeyLen = 128

// evictScan bounds how many entries one eviction looks at.
const evictScan = 64

// Keys that can't be tracked because the map is full of locked-out keys
// are counted in one of overflowShards shared buckets, chosen by hash, so
// they're still limited (fail closed) without one flood locking out every
// new key at once.
const overflowShards = 256

// overflowSeed keys the shard hash, so attackers can't pick which shard
// their keys land in.
var overflowSeed = maphash.MakeSeed()

func overflowKey(key string) string {
	return "\x00overflow:" + strconv.Itoa(int(maphash.String(overflowSeed, key)%overflowShards))
}

// overflowTotalKey caps all overflow attempts together, so spreading keys
// over shards can't multiply an attacker's budget without bound.
const overflowTotalKey = "\x00overflow:total"

// overflowTotalFactor sets the total overflow cap relative to Max.
const overflowTotalFactor = 200

func isOverflow(k string) bool { return strings.HasPrefix(k, "\x00overflow:") }

// overflowFactor sets the overflow bucket's limit relative to Max.
const overflowFactor = 10

// Failures tracks failed attempts.
type Failures struct {
	Max    int
	Window time.Duration
	// MaxKeys caps tracked keys (DefaultMaxKeys if 0).
	MaxKeys int

	mu        sync.Mutex
	hits      map[string][]time.Time
	now       func() time.Time
	lastSweep time.Time
}

// New returns a tracker allowing limit failures per window.
func New(limit int, window time.Duration) *Failures {
	return &Failures{Max: limit, Window: window, hits: map[string][]time.Time{}, now: time.Now}
}

func clip(key string) string {
	if len(key) > maxKeyLen {
		return key[:maxKeyLen]
	}
	return key
}

func (f *Failures) prune(key string, now time.Time) []time.Time {
	kept := f.hits[key][:0]
	for _, t := range f.hits[key] {
		if now.Sub(t) < f.Window {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(f.hits, key)
		return nil
	}
	f.hits[key] = kept
	return kept
}

// Blocked reports whether key has used up its failures, and for how long.
func (f *Failures) Blocked(key string) (bool, time.Duration) {
	key = clip(key)
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	hits := f.prune(key, now)
	if len(hits) < f.Max {
		return false, 0
	}
	return true, f.Window - now.Sub(hits[0])
}

// Fail records a failure.
func (f *Failures) Fail(key string) {
	key = clip(key)
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if !f.record(key, f.prune(key, now), now) {
		ok := overflowKey(key)
		f.hits[ok] = append(f.prune(ok, now), now)
		f.hits[overflowTotalKey] = append(f.prune(overflowTotalKey, now), now)
	}
}

// Attempt atomically checks key and, if it isn't blocked, counts this
// attempt as a failure in advance, so parallel requests can't all slip
// through the check. Call Undo (or Reset) when the attempt succeeds.
func (f *Failures) Attempt(key string) (bool, time.Duration) {
	key = clip(key)
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	hits := f.prune(key, now)
	if len(hits) >= f.Max {
		return false, f.Window - now.Sub(hits[0])
	}
	if !f.record(key, hits, now) {
		// No room to track this key: count it in the shared overflow bucket.
		ok := overflowKey(key)
		over := f.prune(ok, now)
		if len(over) >= f.Max*overflowFactor {
			return false, f.Window - now.Sub(over[0])
		}
		total := f.prune(overflowTotalKey, now)
		if len(total) >= f.Max*overflowTotalFactor {
			return false, f.Window - now.Sub(total[0])
		}
		f.hits[ok] = append(over, now)
		f.hits[overflowTotalKey] = append(total, now)
	}
	return true, 0
}

// Undo removes the most recent attempt recorded for key (or for its
// overflow bucket, if the key wasn't tracked).
func (f *Failures) Undo(key string) {
	key = clip(key)
	f.mu.Lock()
	defer f.mu.Unlock()
	pop := func(k string) {
		if h := f.hits[k]; len(h) > 0 {
			f.hits[k] = h[:len(h)-1]
			if len(f.hits[k]) == 0 {
				delete(f.hits, k)
			}
		}
	}
	if _, tracked := f.hits[key]; tracked {
		pop(key)
		return
	}
	if ok := overflowKey(key); len(f.hits[ok]) > 0 {
		pop(ok)
		pop(overflowTotalKey)
	}
}

// Reset forgets key's failures (after a successful sign-in).
func (f *Failures) Reset(key string) {
	key = clip(key)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hits, key)
}

// record adds a hit and reports whether the key could be tracked. Call
// with f.mu held and hits = f.prune(key, now).
func (f *Failures) record(key string, hits []time.Time, now time.Time) bool {
	limit := f.MaxKeys
	if limit <= 0 {
		limit = DefaultMaxKeys
	}
	if _, exists := f.hits[key]; !exists && len(f.hits) >= limit {
		// Sweep expired keys, but at most once per tenth of the window so a
		// flood of new keys can't make every request walk the whole map.
		if now.Sub(f.lastSweep) >= f.Window/10 {
			f.lastSweep = now
			for k := range f.hits {
				f.prune(k, now)
			}
		}
		if len(f.hits) >= limit && !f.evictOne(now) {
			return false // full of locked-out keys
		}
	}
	f.hits[key] = append(hits, now)
	return true
}

// evictOne drops a random key that isn't locked out, looking at a bounded
// number of entries.
func (f *Failures) evictOne(now time.Time) bool {
	n := 0
	for k, h := range f.hits {
		if n++; n > evictScan {
			return false
		}
		if isOverflow(k) {
			continue
		}
		live := 0
		for _, t := range h {
			if now.Sub(t) < f.Window {
				live++
			}
		}
		if live < f.Max {
			delete(f.hits, k)
			return true
		}
	}
	return false
}
