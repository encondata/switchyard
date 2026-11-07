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
	f.prune(key, now)
	f.hits[key] = append(f.hits[key], now)
	if len(f.hits) > 100_000 { // bound memory under a flood
		for k := range f.hits {
			delete(f.hits, k)
			break
		}
	}
}

// Reset forgets key's failures (after a successful sign-in).
func (f *Failures) Reset(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.hits, key)
}
