package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAPIKeys(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	k, token, err := s.CreateAPIKey(ctx, " Deploy bot ", []string{"hosts.update", "hosts.list", "hosts.list"}, nil, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, APIKeyPrefix) || len(token) < 40 || !strings.HasPrefix(token, k.Prefix) {
		t.Fatalf("token %q, prefix %q", token, k.Prefix)
	}
	if k.Name != "Deploy bot" || strings.Join(k.Permissions, ",") != "hosts.list,hosts.update" {
		t.Fatalf("key = %+v", k)
	}
	var stored int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_keys WHERE token_hash = ?`, token).Scan(&stored)
	if stored != 0 {
		t.Fatal("token stored in plain text")
	}

	got, err := s.APIKeyByToken(ctx, token)
	if err != nil || got.ID != k.ID || !got.Allows("hosts.update") || got.Allows("hosts.delete") {
		t.Fatalf("by token = %+v, %v", got, err)
	}
	for _, bad := range []string{"", "sy_nope", token + "x", strings.TrimPrefix(token, APIKeyPrefix)} {
		if _, err := s.APIKeyByToken(ctx, bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("token %q: %v", bad, err)
		}
	}

	if err := s.TouchAPIKey(ctx, k.ID, "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetAPIKey(ctx, k.ID); got.LastUsedAt == nil || got.LastUsedIP != "203.0.113.5" {
		t.Errorf("last used = %v %q", got.LastUsedAt, got.LastUsedIP)
	}

	// Edit permissions; the token keeps working.
	if _, err := s.UpdateAPIKey(ctx, k.ID, "Deploy bot", []string{"hosts.list"}, nil, "admin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.APIKeyByToken(ctx, token); got.Allows("hosts.update") || !got.Allows("hosts.list") {
		t.Errorf("after edit = %v", got.Permissions)
	}

	// Validation.
	var verr ValidationError
	if _, _, err := s.CreateAPIKey(ctx, "", nil, nil, "admin"); !errors.As(err, &verr) || verr["name"] == "" || verr["permissions"] == "" {
		t.Errorf("empty key err = %v", err)
	}
	past := time.Now().Add(-time.Hour)
	if _, _, err := s.CreateAPIKey(ctx, "x", []string{"hosts.list"}, &past, "admin"); !errors.As(err, &verr) {
		t.Errorf("past expiry err = %v", err)
	}

	// Expiry.
	soon := time.Now().Add(time.Hour)
	k2, tok2, err := s.CreateAPIKey(ctx, "Short", []string{"stats.overview"}, &soon, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIKeyByToken(ctx, tok2); err != nil {
		t.Fatal(err)
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Minute).UTC(), k2.ID)
	if _, err := s.APIKeyByToken(ctx, tok2); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired key still works: %v", err)
	}

	// Revoke.
	if err := s.RevokeAPIKey(ctx, k.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIKeyByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked key still works: %v", err)
	}
	if err := s.RevokeAPIKey(ctx, k.ID, "admin"); err != nil {
		t.Errorf("revoking twice: %v", err)
	}
	if _, err := s.UpdateAPIKey(ctx, k.ID, "x", []string{"hosts.list"}, nil, "admin"); err == nil {
		t.Error("revoked key edited")
	}
	keys, _ := s.ListAPIKeys(ctx)
	if len(keys) != 2 || keys[len(keys)-1].ID != k.ID {
		t.Errorf("list = %+v (revoked last)", keys)
	}
}
