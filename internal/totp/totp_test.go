package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, 8-digit values truncated to 6.
func TestRFCVectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for unix, want := range cases {
		got, err := Code(secret, Step(time.Unix(unix, 0)))
		if err != nil || got != want {
			t.Errorf("t=%d: %s, %v; want %s", unix, got, err, want)
		}
	}
}

func TestVerify(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, _ := Code(secret, Step(now))
	step, ok := Verify(secret, code[:3]+" "+code[3:], now, 0)
	if !ok || step != Step(now) {
		t.Fatal("current code rejected")
	}
	if _, ok := Verify(secret, code, now, step); ok {
		t.Fatal("reused code accepted")
	}
	prev, _ := Code(secret, Step(now)-1)
	if _, ok := Verify(secret, prev, now, 0); !ok {
		t.Fatal("previous step should be accepted for clock drift")
	}
	old, _ := Code(secret, Step(now)-3)
	if _, ok := Verify(secret, old, now, 0); ok {
		t.Fatal("old code accepted")
	}
	if _, ok := Verify(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
	u := URI("CPM", "admin", secret)
	if !strings.HasPrefix(u, "otpauth://totp/CPM:admin?") || !strings.Contains(u, "secret="+secret) {
		t.Fatalf("URI = %s", u)
	}
}
