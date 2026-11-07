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
