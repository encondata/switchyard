package purelymail

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPI(t *testing.T) {
	var got []string // operation and body, per call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s %s with %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Purelymail-Api-Token") != "good-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"type":"error","code":"invalidToken","message":"Invalid API token"}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := json.Marshal(body)
		got = append(got, r.URL.Path+" "+string(b))
		switch r.URL.Path {
		case "/getOwnershipCode":
			_, _ = w.Write([]byte(`{"type":"success","result":{"code":"purelymail_ownership_proof=abc"}}`))
		case "/listDomains":
			_, _ = w.Write([]byte(`{"type":"success","result":{"domains":[{"name":"Example.com","isShared":false,"dnsSummary":{"passesMx":true,"passesSpf":true,"passesDkim":false,"passesDmarc":true}}]}}`))
		case "/addDomain":
			if body["domainName"] == "fails.test" {
				_, _ = w.Write([]byte(`{"type":"error","code":"domainCheckFailed","message":"Ownership record not found"}`))
				return
			}
			_, _ = w.Write([]byte(`{"type":"success","result":{}}`))
		case "/updateDomainSettings":
			_, _ = w.Write([]byte(`{"result":{}}`)) // the spec's shape, without "type"
		}
	}))
	defer srv.Close()
	APIBaseURL = srv.URL
	ctx := context.Background()
	c := Client{Token: "good-key"}

	if code, err := c.OwnershipCode(ctx); err != nil || code != "purelymail_ownership_proof=abc" {
		t.Fatalf("OwnershipCode = %q, %v", code, err)
	}
	d, err := c.FindDomain(ctx, "example.com")
	if err != nil || d == nil || d.DNSSummary.PassesDkim || !d.DNSSummary.PassesMx || d.DNSSummary.AllPass() {
		t.Fatalf("FindDomain = %+v, %v", d, err)
	}
	if d, err := c.FindDomain(ctx, "other.test"); err != nil || d != nil {
		t.Fatalf("FindDomain(other) = %+v, %v", d, err)
	}
	if err := c.AddDomain(ctx, "new.test"); err != nil {
		t.Fatal(err)
	}
	err = c.AddDomain(ctx, "fails.test")
	var pe *APIError
	if !errors.As(err, &pe) || pe.BadKey() || err.Error() != "purelymail: Ownership record not found (domainCheckFailed)" {
		t.Fatalf("AddDomain(fails) err = %v", err)
	}
	if err := c.RecheckDNS(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`/getOwnershipCode {}`,
		`/listDomains {"includeShared":false}`,
		`/listDomains {"includeShared":false}`,
		`/addDomain {"domainName":"new.test"}`,
		`/addDomain {"domainName":"fails.test"}`,
		`/updateDomainSettings {"name":"example.com","recheckDns":true}`,
	}
	if len(got) != len(want) {
		t.Fatalf("calls = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d = %s, want %s", i, got[i], want[i])
		}
	}

	_, err = Client{Token: "bad"}.OwnershipCode(ctx)
	if !errors.As(err, &pe) || !pe.BadKey() {
		t.Fatalf("bad key err = %v", err)
	}
}
