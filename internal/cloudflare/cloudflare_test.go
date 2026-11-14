package cloudflare

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if r.Owner != "user" {
		t.Errorf("owner = %q", r.Owner)
	}
	_, err = Verify(context.Background(), "bad")
	if err == nil || !strings.HasPrefix(err.Error(), "cloudflare: Invalid API Token. Cloudflare doesn't accept this token") {
		t.Fatalf("Verify(bad) err = %v", err)
	}
}

// Account-owned tokens are "invalid" at /user/tokens/verify and verify at
// their account instead.
func TestVerifyAccountToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer acct" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`))
			return
		}
		switch r.URL.Path {
		case "/user/tokens/verify":
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`))
		case "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"example.com","account":{"id":"a1"}}]}`))
		case "/accounts/a1/tokens/verify":
			_, _ = w.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"no route"}]}`))
		}
	}))
	defer srv.Close()
	BaseURL = srv.URL

	r, err := Verify(context.Background(), "acct")
	if err != nil || !r.Active || r.Owner != "account" || len(r.Zones) != 1 {
		t.Fatalf("Verify(acct) = %+v, %v", r, err)
	}
	_, err = Verify(context.Background(), "nope")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != 1000 || !ae.BadToken() || !strings.Contains(err.Error(), "(code 1000)") {
		t.Fatalf("Verify(nope) err = %v", err)
	}
}

func TestAPIErrorText(t *testing.T) {
	for _, c := range []struct {
		e    APIError
		want string
	}{
		{APIError{Status: 400, Code: 6003, Message: "Invalid request headers: Invalid format for Authorization header"},
			"cloudflare: Invalid request headers: Invalid format for Authorization header (code 6003). Cloudflare couldn't read the token. Paste only the API token itself (not the Global API Key)"},
		{APIError{Status: 403, Code: 10000, Message: "Authentication error"},
			"cloudflare: Authentication error (code 10000). The token works but isn't allowed to do this: give it Zone → Zone → Read and Zone → DNS → Edit on this zone"},
		{APIError{Status: 502}, "cloudflare: HTTP 502"},
	} {
		if got := c.e.Error(); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}

func TestRecords(t *testing.T) {
	var created string
	var deleted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "example.com" {
				_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"example.com"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		case r.Method == "GET" && r.URL.Path == "/zones/z1/dns_records":
			if r.URL.Query().Get("page") == "1" {
				_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"r1","type":"MX","name":"example.com","content":"mx.example.net","priority":10}],"result_info":{"total_pages":2}}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"r2","type":"TXT","name":"example.com","content":"\"v=spf1 -all\""}],"result_info":{"total_pages":2}}`))
		case r.Method == "POST" && r.URL.Path == "/zones/z1/dns_records":
			b, _ := io.ReadAll(r.Body)
			created = string(b)
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"r3","type":"MX","name":"example.com","content":"mailserver.purelymail.com","priority":50}}`))
		case r.Method == "DELETE" && r.URL.Path == "/zones/z1/dns_records/r1":
			deleted = "r1"
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"r1"}}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"no route"}]}`))
		}
	}))
	defer srv.Close()
	BaseURL = srv.URL
	ctx := context.Background()

	// mail.example.com isn't a zone; its parent is.
	z, err := FindZone(ctx, "t", "mail.example.com")
	if err != nil || z.ID != "z1" {
		t.Fatalf("FindZone = %+v, %v", z, err)
	}
	if _, err := FindZone(ctx, "t", "other.test"); !errors.Is(err, ErrNoZone) {
		t.Fatalf("FindZone(other) err = %v", err)
	}
	rs, err := ListRecords(ctx, "t", "z1")
	if err != nil || len(rs) != 2 || *rs[0].Priority != 10 || rs[1].Content != `"v=spf1 -all"` {
		t.Fatalf("ListRecords = %+v, %v", rs, err)
	}
	p := 50
	got, err := CreateRecord(ctx, "t", "z1", Record{ID: "ignored", Type: "MX", Name: "example.com", Content: "mailserver.purelymail.com", Priority: &p, TTL: 1})
	if err != nil || got.ID != "r3" {
		t.Fatalf("CreateRecord = %+v, %v", got, err)
	}
	if created != `{"type":"MX","name":"example.com","content":"mailserver.purelymail.com","priority":50,"ttl":1,"proxied":false}` {
		t.Errorf("create body = %s", created)
	}
	if err := DeleteRecord(ctx, "t", "z1", "r1"); err != nil || deleted != "r1" {
		t.Fatalf("DeleteRecord err = %v", err)
	}
	if err := DeleteRecord(ctx, "t", "z1", "nope"); err == nil || err.Error() != "cloudflare: no route" {
		t.Fatalf("DeleteRecord(nope) err = %v", err)
	}
}
