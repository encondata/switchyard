package store

import (
	"context"
	"errors"
	"testing"
)

func TestPrefs(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	u, err := s.Authenticate(ctx, "admin", DefaultAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s.GetPrefs(ctx, u.ID); err != nil || p.Accent != "" {
		t.Fatalf("default prefs = %+v, %v", p, err)
	}
	if p, err := s.SetPrefs(ctx, u.ID, Prefs{Accent: " #2563EB "}); err != nil || p.Accent != "#2563eb" {
		t.Fatalf("set = %+v, %v", p, err)
	}
	if p, _ := s.GetPrefs(ctx, u.ID); p.Accent != "#2563eb" {
		t.Fatalf("saved accent = %q", p.Accent)
	}
	for _, bad := range []string{"blue", "#fff", "#ffff00", "#12345g"} {
		var verr ValidationError
		if _, err := s.SetPrefs(ctx, u.ID, Prefs{Accent: bad}); !errors.As(err, &verr) {
			t.Errorf("accent %q accepted (err %v)", bad, err)
		}
	}
	if p, _ := s.SetPrefs(ctx, u.ID, Prefs{}); p.Accent != "" {
		t.Fatalf("reset = %+v", p)
	}
}
