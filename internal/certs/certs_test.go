package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCert(t *testing.T, dir string, names []string, notAfter time.Time) {
	t.Helper()
	writeCertLife(t, dir, names, notAfter.Add(-90*24*time.Hour), notAfter)
}

func writeCertLife(t *testing.T, dir string, names []string, notBefore, notAfter time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]},
		Issuer: pkix.Name{CommonName: "Test CA"}, DNSNames: names,
		NotBefore: notBefore, NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, names[0]+".crt")
	if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanAndStatus(t *testing.T) {
	data := t.TempDir()
	now := time.Now()
	base := filepath.Join(data, "caddy", "certificates")
	writeCert(t, filepath.Join(base, "local", "app.localhost"), []string{"app.localhost"}, now.Add(6*24*time.Hour))
	writeCert(t, filepath.Join(base, "acme", "example.com"), []string{"example.com"}, now.Add(80*24*time.Hour))
	writeCert(t, filepath.Join(base, "acme", "wild.example.com"), []string{"*.lan.example.com"}, now.Add(80*24*time.Hour))
	writeCert(t, filepath.Join(base, "acme", "old.example.com"), []string{"old.example.com"}, now.Add(-time.Hour))
	// A 12-hour internal cert with 6 hours left is on Caddy's normal schedule.
	writeCertLife(t, filepath.Join(base, "local", "short.localhost"), []string{"short.localhost"}, now.Add(-6*time.Hour), now.Add(6*time.Hour))

	all, err := Scan(data)
	if err != nil || len(all) != 5 {
		t.Fatalf("Scan = %d certs, %v", len(all), err)
	}
	want := map[string]string{
		"app.localhost":       "expiring",
		"example.com":         "valid",
		"nas.lan.example.com": "valid",
		"a.b.lan.example.com": "pending", // wildcard covers one label only
		"old.example.com":     "expired",
		"new.example.com":     "pending",
		"short.localhost":     "valid",
	}
	for d, state := range want {
		if got := For(d, all, now); got.State != state {
			t.Errorf("%s: state = %s, want %s", d, got.State, state)
		}
	}
	// Self-signed in this test, so the issuer is the cert's own name.
	if s := For("app.localhost", all, now); s.Source != "local" || s.Issuer != "app.localhost" {
		t.Errorf("app.localhost source/issuer = %s/%s", s.Source, s.Issuer)
	}
}

func TestScanMissingDir(t *testing.T) {
	all, err := Scan(filepath.Join(t.TempDir(), "nope"))
	if err != nil || len(all) != 0 {
		t.Fatalf("Scan(missing) = %v, %v", all, err)
	}
}
