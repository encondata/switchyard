package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"Invalid API Token"}]}`))
			return
		}
		switch r.URL.Path {
		case "/user/tokens/verify":
			_, _ = w.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
		case "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"name":"z.example"},{"name":"a.example"}]}`))
		}
	}))
	defer srv.Close()
	BaseURL = srv.URL

	r, err := Verify(context.Background(), "good")
	if err != nil || !r.Active || len(r.Zones) != 2 || r.Zones[0] != "a.example" {
		t.Fatalf("Verify(good) = %+v, %v", r, err)
	}
	if _, err := Verify(context.Background(), "bad"); err == nil || err.Error() != "cloudflare: Invalid API Token" {
		t.Fatalf("Verify(bad) err = %v", err)
	}
}
