package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

var key = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

func TestSealOpen(t *testing.T) {
	b, err := New(key)
	if err != nil || !b.Ready() {
		t.Fatalf("New = %v, %v", b, err)
	}
	s1, _ := b.Seal("token-value", "dns:1")
	s2, _ := b.Seal("token-value", "dns:1")
	if s1 == s2 || strings.Contains(s1, "token-value") {
		t.Fatal("sealing must be randomized and hide the plaintext")
	}
	if pt, err := b.Open(s1, "dns:1"); err != nil || pt != "token-value" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	if _, err := b.Open(s1, "dns:2"); err == nil {
		t.Fatal("opened with the wrong purpose")
	}
	other, _ := New(hex.EncodeToString([]byte("fedcba9876543210fedcba9876543210")))
	if _, err := other.Open(s1, "dns:1"); err == nil {
		t.Fatal("opened with the wrong key")
	}
	tampered := s1[:len(s1)-2] + "AA"
	if _, err := b.Open(tampered, "dns:1"); err == nil {
		t.Fatal("opened tampered ciphertext")
	}
}

func TestNoKey(t *testing.T) {
	b, err := New("")
	if err != nil || b.Ready() {
		t.Fatalf("New(\"\") = %v, %v", b, err)
	}
	if _, err := b.Seal("x", "p"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Seal without key err = %v", err)
	}
	if _, err := New("too-short"); err == nil {
		t.Fatal("short key accepted")
	}
}
