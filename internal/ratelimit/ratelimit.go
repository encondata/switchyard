// Package ratelimit counts failures per key (IP address, username) in a
// sliding window, to slow down password guessing.
package ratelimit

import (
	"sync"
	"time"
)

// Failures tracks failed attempts.
type Failures struct {
	Max    int
	Window time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time
	now  func() time.Time
}

// New returns a tracker allowing limit failures per window.
func New(limit int, window time.Duration) *Failures {
	return &Failures{Max: limit, Window: window, hits: map[string][]time.Time{}, now: time.Now}
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
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	f.record(key, f.prune(key, now), now)
}

// maxKeys bounds memory when many different keys (IPs, usernames) fail.
const maxKeys = 100_000

// maxKeyLen bounds the memory one key can use.
const maxKeyLen = 128

// record adds a hit. Call with f.mu held and hits = f.prune(key, now).
func (f *Failures) record(key string, hits []time.Time, now time.Time) {
	if len(key) > maxKeyLen {
		key = key[:maxKeyLen]
	}
	if _, exists := f.hits[key]; !exists && len(f.hits) >= maxKeys {
		// Sweep expired keys first; if still full, drop an arbitrary one.
		for k := range f.hits {
			f.prune(k, now)
		}
		for k := range f.hits {
			if len(f.hits) < maxKeys {
				break
			}
			delete(f.hits, k)
		}
	}
	f.hits[key] = append(hits, now)
}

// Attempt atomically checks key and, if it isn't blocked, counts this
// attempt as a failure in advance, so parallel requests can't all slip
// through the check. Call Undo (or Reset) when the attempt succeeds.
func (f *Failures) Attempt(key string) (bool, time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	hits := f.prune(key, now)
	if len(hits) >= f.Max {
		return false, f.Window - now.Sub(hits[0])
	}
	f.record(key, hits, now)
	return true, 0
}

// Undo removes the most recent attempt recorded for key.
func (f *Failures) Undo(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h := f.hits[key]; len(h) > 0 {
		f.hits[key] = h[:len(h)-1]
		if len(f.hits[key]) == 0 {
			delete(f.hits, key)
		}
	}
}

// Reset forgets key's failures (after a successful sign-in).
func (f *Failures) Reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hits, key)
}
