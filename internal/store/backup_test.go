package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveHost(ctx, proxyHost("backup.example.com"), "admin"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "b.db")
	if err := s.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackup(ctx, dest); err != nil {
		t.Fatalf("valid backup rejected: %v", err)
	}
	restored, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restored.Close() }()
	hosts, _ := restored.ListHosts(ctx)
	if len(hosts) != 1 || hosts[0].Domains[0] != "backup.example.com" {
		t.Fatalf("restored hosts = %+v", hosts)
	}

	junk := filepath.Join(t.TempDir(), "junk.db")
	_ = os.WriteFile(junk, []byte("hello"), 0o600)
	var conflict ConflictError
	if err := ValidateBackup(ctx, junk); !errors.As(err, &conflict) {
		t.Fatalf("junk file err = %v", err)
	}
}
