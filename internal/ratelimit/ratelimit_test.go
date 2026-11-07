package ratelimit

import (
	"strconv"
	"testing"
	"time"
)

func TestFailures(t *testing.T) {
	now := time.Unix(1000, 0)
	f := New(3, time.Minute)
	f.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if b, _ := f.Blocked("ip"); b {
			t.Fatalf("blocked after %d failures", i)
		}
		f.Fail("ip")
	}
	b, wait := f.Blocked("ip")
	if !b || wait != time.Minute {
		t.Fatalf("Blocked = %v, %v", b, wait)
	}
	if b, _ := f.Blocked("other"); b {
		t.Fatal("other key blocked")
	}
	now = now.Add(61 * time.Second)
	if b, _ := f.Blocked("ip"); b {
		t.Fatal("still blocked after the window")
	}
	f.Fail("ip")
	f.Reset("ip")
	if b, _ := f.Blocked("ip"); b {
		t.Fatal("blocked after reset")
	}
}

func TestAttempt(t *testing.T) {
	f := New(2, time.Minute)
	if ok, _ := f.Attempt("k"); !ok {
		t.Fatal("first attempt refused")
	}
	if ok, _ := f.Attempt("k"); !ok {
		t.Fatal("second attempt refused")
	}
	if ok, _ := f.Attempt("k"); ok {
		t.Fatal("third attempt allowed: attempts must count before the result is known")
	}
	f.Undo("k")
	if ok, _ := f.Attempt("k"); !ok {
		t.Fatal("undo didn't free a slot")
	}
}

func TestKeyCap(t *testing.T) {
	f := New(2, time.Minute)
	f.MaxKeys = 1000
	f.Attempt("victim")
	f.Attempt("victim") // locked out
	for i := 0; i < 5000; i++ {
		f.Attempt(time.Duration(i).String())
	}
	if len(f.hits) > f.MaxKeys {
		t.Fatalf("keys = %d, want at most %d", len(f.hits), f.MaxKeys)
	}
	if ok, _ := f.Attempt("victim"); ok {
		t.Fatal("a locked-out key was evicted")
	}
}

func TestOverflowFailsClosed(t *testing.T) {
	f := New(1, time.Minute)
	f.MaxKeys = 3
	for _, k := range []string{"a", "b", "c"} {
		f.Attempt(k) // each now locked out (Max 1)
	}
	// Untracked keys are still limited, per overflow shard.
	allowed := 0
	for i := 0; i < 50; i++ {
		if ok, _ := f.Attempt("same-shard"); ok {
			allowed++
		}
	}
	if allowed != f.Max*overflowFactor {
		t.Fatalf("untracked key allowed %d times, want %d", allowed, f.Max*overflowFactor)
	}
	// A different key usually lands in another shard and isn't affected.
	other := ""
	for i := 0; i < 1000; i++ {
		k := "k" + strconv.Itoa(i)
		if overflowKey(k) != overflowKey("same-shard") {
			other = k
			break
		}
	}
	if ok, _ := f.Attempt(other); !ok {
		t.Fatal("one full overflow shard blocked an unrelated key")
	}
	// Undo releases the overflow hit for an untracked key.
	before := len(f.hits[overflowTotalKey])
	f.Undo(other)
	if n := len(f.hits[overflowKey(other)]); n != 0 {
		t.Fatalf("overflow hits after undo = %d", n)
	}
	if n := len(f.hits[overflowTotalKey]); n != before-1 {
		t.Fatalf("overflow total after undo = %d, want %d", n, before-1)
	}
}
