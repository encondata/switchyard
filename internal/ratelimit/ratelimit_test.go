package ratelimit

import (
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
