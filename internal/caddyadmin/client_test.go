package caddyadmin

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unixServer starts h on a unix socket and returns the socket path.
func unixServer(t *testing.T, h http.Handler) string {
	t.Helper()
	// Keep the path short: unix socket paths are limited to ~104 bytes on macOS.
	dir, err := os.MkdirTemp("", "cpm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

func TestConfig(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/" || r.Host != "localhost" {
			http.Error(w, "unexpected "+r.Host+r.URL.Path, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"admin":{}}`))
	}))
	got, err := New(sock).Config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"admin":{}}` {
		t.Fatalf("config = %s", got)
	}
}

func TestConfigHTTPError(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusForbidden)
	}))
	_, err := New(sock).Config(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want HTTP 403", err)
	}
}

func TestConfigNoSocket(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "missing.sock")).Config(context.Background()); err == nil {
		t.Fatal("expected an error for a missing socket")
	}
}
