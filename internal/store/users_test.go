package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestDefaultAdmin(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	created, err := s.EnsureDefaultAdmin(ctx)
	if err != nil || !created {
		t.Fatalf("first EnsureDefaultAdmin = %v, %v; want true, nil", created, err)
	}
	if created, err = s.EnsureDefaultAdmin(ctx); err != nil || created {
		t.Fatalf("second EnsureDefaultAdmin = %v, %v; want false, nil", created, err)
	}

	u, err := s.Authenticate(ctx, "admin", "123456")
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != "admin" || !u.MustChangePassword {
		t.Fatalf("user = %+v, want admin role with must_change_password", u)
	}
	if _, err := s.Authenticate(ctx, "ADMIN", "123456"); err != nil {
		t.Fatalf("username should be case-insensitive: %v", err)
	}
	if _, err := s.Authenticate(ctx, "admin", "wrong"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
	if _, err := s.Authenticate(ctx, "nobody", "123456"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user err = %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	u, _ := s.Authenticate(ctx, "admin", "123456")
	keep, _ := s.CreateSession(ctx, u.ID, time.Hour)
	other, _ := s.CreateSession(ctx, u.ID, time.Hour)

	if err := s.ChangePassword(ctx, u.ID, "wrong", "n3w-passw0rd", keep); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong current password err = %v", err)
	}
	if err := s.ChangePassword(ctx, u.ID, "123456", "n3w-passw0rd", keep); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "admin", "123456"); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("old password still works")
	}
	u, err := s.Authenticate(ctx, "admin", "n3w-passw0rd")
	if err != nil || u.MustChangePassword {
		t.Fatalf("after change: %+v, %v", u, err)
	}
	if _, err := s.SessionUser(ctx, keep); err != nil {
		t.Fatalf("current session should survive: %v", err)
	}
	if _, err := s.SessionUser(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other session should be signed out, err = %v", err)
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	u, _ := s.Authenticate(ctx, "admin", "123456")

	tok, err := s.CreateSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.SessionUser(ctx, tok); err != nil || got.ID != u.ID {
		t.Fatalf("SessionUser = %+v, %v", got, err)
	}
	if err := s.DeleteSession(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session err = %v", err)
	}

	expired, _ := s.CreateSession(ctx, u.ID, -time.Minute)
	if _, err := s.SessionUser(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session err = %v", err)
	}
}

func TestReopenKeepsData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "cpm.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen (migrations must be idempotent): %v", err)
	}
	defer func() { _ = s.Close() }()
	if created, _ := s.EnsureDefaultAdmin(ctx); created {
		t.Fatal("default admin recreated on reopen")
	}
}
