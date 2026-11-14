package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/encondata/switchyard/internal/cloudflare"
	"github.com/encondata/switchyard/internal/secrets"
	"github.com/encondata/switchyard/internal/store"
)

// fakeZone is one Cloudflare zone (example.com, id z1) held in memory.
type fakeZone struct {
	mu   sync.Mutex
	recs []cloudflare.Record
	next int
}

func (f *fakeZone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = w.Write([]byte(`{"success":true,"result":` + string(b) + `,"result_info":{"total_pages":1}}`))
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			reply([]cloudflare.Zone{{ID: "z1", Name: "example.com"}})
			return
		}
		reply([]cloudflare.Zone{})
	case r.Method == "GET" && r.URL.Path == "/zones/z1/dns_records":
		reply(f.recs)
	case r.Method == "POST" && r.URL.Path == "/zones/z1/dns_records":
		var rec cloudflare.Record
		_ = json.NewDecoder(r.Body).Decode(&rec)
		f.next++
		rec.ID = "n" + strconv.Itoa(f.next)
		f.recs = append(f.recs, rec)
		reply(rec)
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
		id := strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/")
		for i, rec := range f.recs {
			if rec.ID == id {
				f.recs = append(f.recs[:i], f.recs[i+1:]...)
				reply(map[string]string{"id": id})
				return
			}
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"Record not found"}]}`))
	default:
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"no route"}]}`))
	}
}

func TestMailDomainsAPI(t *testing.T) {
	ctx := context.Background()
	prio := 1
	zone := &fakeZone{recs: []cloudflare.Record{
		{ID: "g1", Type: "MX", Name: "example.com", Content: "aspmx.l.google.com", Priority: &prio},
		{ID: "g2", Type: "TXT", Name: "example.com", Content: `"v=spf1 include:_spf.google.com ~all"`},
		{ID: "w1", Type: "A", Name: "www.example.com", Content: "192.0.2.1"},
	}}
	cf := httptest.NewServer(zone)
	t.Cleanup(cf.Close)
	old := cloudflare.BaseURL
	cloudflare.BaseURL = cf.URL
	t.Cleanup(func() { cloudflare.BaseURL = old })

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.New(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	p, err := st.SaveDNSProvider(ctx, store.DNSProvider{Name: "cf"}, "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-Ab", box, "admin")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(Options{Version: "test", UI: testUI(), Store: st, Box: box}))
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: ts.URL, http: &http.Client{Jar: jar}}
	c.do("POST", "/api/auth/login", `{"username":"admin","password":"123456"}`)
	if code, _ := c.do("POST", "/api/auth/password", `{"current_password":"123456","new_password":"a-good-passw0rd"}`); code != 200 {
		t.Fatalf("password change = %d", code)
	}

	if code, body := c.do("PUT", "/api/mail/settings", `{"ownership":"purelymail_ownership_proof=abc"}`); code != 200 || body["ownership"] != "purelymail_ownership_proof=abc" {
		t.Fatalf("settings = %d %v", code, body)
	}
	pid := strconv.FormatInt(p.ID, 10)
	if code, body := c.do("POST", "/api/mail/domains", `{"domain":"other.test","dns_provider_id":`+pid+`}`); code != 400 {
		t.Fatalf("unknown zone = %d %v", code, body)
	}

	code, body := c.do("POST", "/api/mail/domains", `{"domain":"example.com","dns_provider_id":`+pid+`}`)
	if code != 201 {
		t.Fatalf("create = %d %v", code, body)
	}
	dom := body["domain"].(map[string]any)
	id := strconv.Itoa(int(dom["id"].(float64)))
	if dom["status"] != "conflict" || dom["zone_id"] != "z1" {
		t.Fatalf("created domain = %v", dom)
	}
	if n := len(body["records"].([]any)); n != 7 {
		t.Fatalf("records = %d", n)
	}
	if len(zone.recs) != 3 {
		t.Fatalf("adding a domain changed DNS: %+v", zone.recs)
	}

	// Without replace, the Google MX and SPF stay and their records aren't added.
	code, body = c.do("POST", "/api/mail/domains/"+id+"/records", `{"replace":[]}`)
	if code != 200 || len(body["changes"].([]any)) != 5 {
		t.Fatalf("apply = %d %v", code, body)
	}
	if body["domain"].(map[string]any)["status"] != "conflict" {
		t.Fatalf("status after first apply = %v", body["domain"])
	}

	// Replacing them finishes the job.
	code, body = c.do("POST", "/api/mail/domains/"+id+"/records", `{"replace":["mx","spf"]}`)
	if code != 200 || len(body["changes"].([]any)) != 4 {
		t.Fatalf("apply replace = %d %v", code, body)
	}
	if body["domain"].(map[string]any)["status"] != "ok" {
		t.Fatalf("status after replace = %v", body)
	}
	for _, r := range zone.recs {
		if r.ID == "g1" || r.ID == "g2" {
			t.Errorf("old record %s still there", r.ID)
		}
	}
	if len(zone.recs) != 8 { // 7 Purelymail records and the A record
		t.Errorf("zone has %d records: %+v", len(zone.recs), zone.recs)
	}

	// Checking again is clean; removing the domain leaves DNS alone.
	if code, body = c.do("GET", "/api/mail/domains/"+id+"/records", ""); code != 200 || body["domain"].(map[string]any)["status"] != "ok" {
		t.Fatalf("check = %d %v", code, body)
	}
	if code, _ = c.do("DELETE", "/api/mail/domains/"+id, ""); code != 204 {
		t.Fatalf("delete = %d", code)
	}
	if len(zone.recs) != 8 {
		t.Errorf("deleting the domain changed DNS")
	}

	// The audit log keeps the deleted records.
	entries, _ := st.ListAudit(ctx, 0, "mail_domain", "", 50)
	found := false
	for _, e := range entries {
		if e.Action == "dns_records" && strings.Contains(e.After, "aspmx.l.google.com") {
			found = true
		}
	}
	if !found {
		t.Errorf("audit lacks the deleted MX: %+v", entries)
	}
}
