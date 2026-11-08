package unifi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/encondata/switchyard/internal/secrets"
	"github.com/encondata/switchyard/internal/store"
)

const site = "88f7af54-98f8-306a-a1c7-c9349722b1f6"

// fakeConsole answers like the UniFi Network Integration API (10.6),
// over TLS with a self-signed certificate.
type fakeConsole struct {
	mu        sync.Mutex
	key       string
	lists     map[string]List
	policies  []map[string]any
	puts      int
	keyedReqs int // requests that carried the right key
	nextID    int
}

func (f *fakeConsole) handler(t *testing.T) http.Handler {
	base := "/proxy/network/integration/v1/sites"
	write := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	pageOf := func(items []any) map[string]any {
		return map[string]any{"offset": 0, "limit": 200, "count": len(items), "totalCount": len(items), "data": items}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("X-API-Key") != f.key {
			write(w, 401, map[string]any{"statusCode": 401, "code": "api.authentication.missing-credentials", "message": "Missing credentials"})
			return
		}
		f.keyedReqs++
		switch {
		case r.Method == "GET" && r.URL.Path == base:
			write(w, 200, pageOf([]any{map[string]any{"id": site, "internalReference": "default", "name": "Home"}}))
		case r.Method == "GET" && r.URL.Path == base+"/"+site+"/traffic-matching-lists":
			var out []any
			for _, l := range f.lists {
				out = append(out, map[string]any{"id": l.ID, "name": l.Name, "type": l.Type})
			}
			write(w, 200, pageOf(out))
		case r.Method == "POST" && r.URL.Path == base+"/"+site+"/traffic-matching-lists":
			var l List
			_ = json.NewDecoder(r.Body).Decode(&l)
			if len(l.Items) == 0 || l.Name == "" {
				write(w, 400, map[string]any{"statusCode": 400, "message": "items: size must be at least 1"})
				return
			}
			f.nextID++
			l.ID = fmt.Sprintf("00000000-0000-4000-8000-%012d", f.nextID)
			f.lists[l.ID] = l
			write(w, 201, l)
		case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, base+"/"+site+"/traffic-matching-lists/"):
			id := strings.TrimPrefix(r.URL.Path, base+"/"+site+"/traffic-matching-lists/")
			old, ok := f.lists[id]
			if !ok {
				write(w, 404, map[string]any{"statusCode": 404, "message": "Not found"})
				return
			}
			var l List
			_ = json.NewDecoder(r.Body).Decode(&l)
			if len(l.Items) == 0 || l.Type != old.Type {
				write(w, 400, map[string]any{"statusCode": 400, "message": "bad list"})
				return
			}
			l.ID = id
			f.lists[id] = l
			f.puts++
			write(w, 200, l)
		case r.Method == "GET" && r.URL.Path == base+"/"+site+"/firewall/policies":
			var out []any
			for _, p := range f.policies {
				out = append(out, p)
			}
			write(w, 200, pageOf(out))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			write(w, 404, map[string]any{"statusCode": 404, "message": "Not found"})
		}
	})
}

func newConsole(t *testing.T) (*fakeConsole, *httptest.Server) {
	f := &fakeConsole{key: "unifi-test-key", lists: map[string]List{}}
	ts := httptest.NewTLSServer(f.handler(t))
	t.Cleanup(ts.Close)
	return f, ts
}

func TestCertificatePinning(t *testing.T) {
	f, ts := newConsole(t)
	ctx := context.Background()
	info, err := FetchCert(ctx, ts.URL)
	if err != nil || len(info.SHA256) != 64 || info.Valid {
		t.Fatalf("FetchCert = %+v, %v (self-signed: not valid)", info, err)
	}
	if f.keyedReqs != 0 {
		t.Fatal("fetching the certificate sent a request")
	}
	// Normal checks reject the self-signed certificate, without sending the key.
	if _, err := (&Client{BaseURL: ts.URL, APIKey: f.key}).Sites(ctx); err == nil || !strings.Contains(err.Error(), "Check connection") {
		t.Errorf("unpinned = %v", err)
	}
	// A wrong pin: refused before any request.
	wrong := strings.Repeat("ab", 32)
	if _, err := (&Client{BaseURL: ts.URL, APIKey: f.key, CertSHA256: wrong}).Sites(ctx); !errors.Is(err, ErrCertChanged) {
		t.Errorf("wrong pin = %v", err)
	}
	if f.keyedReqs != 0 {
		t.Fatal("the key was sent to an untrusted console")
	}
	// The right pin works.
	sites, err := (&Client{BaseURL: ts.URL, APIKey: f.key, CertSHA256: strings.ToUpper(info.SHA256)}).Sites(ctx)
	if err != nil || len(sites) != 1 || sites[0].ID != site || sites[0].Name != "Home" {
		t.Fatalf("pinned sites = %+v, %v", sites, err)
	}
	// A wrong key.
	if _, err := (&Client{BaseURL: ts.URL, APIKey: "nope", CertSHA256: info.SHA256}).Sites(ctx); err == nil || !strings.Contains(err.Error(), "didn't accept the API key") {
		t.Errorf("wrong key = %v", err)
	}
	if got := Fingerprint("ab01"); got != "AB:01" {
		t.Errorf("Fingerprint = %q", got)
	}
}

func TestItems(t *testing.T) {
	v4, v6 := Items([]string{"203.0.113.9", "198.51.100.0/24", "203.0.113.9/32", "::ffff:192.0.2.7", "2001:db8::1", "2001:db8:1::/48", "junk"})
	got4 := fmt.Sprint(v4)
	if got4 != "[{IP_ADDRESS 192.0.2.7} {SUBNET 198.51.100.0/24} {IP_ADDRESS 203.0.113.9}]" {
		t.Errorf("v4 = %s", got4)
	}
	if fmt.Sprint(v6) != "[{SUBNET 2001:db8:1::/48} {IP_ADDRESS 2001:db8::1}]" {
		t.Errorf("v6 = %v", v6)
	}
}

func TestSync(t *testing.T) {
	f, ts := newConsole(t)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	box, err := secrets.New(base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := FetchCert(ctx, ts.URL)
	if _, err := st.SaveUniFi(ctx, store.UniFiSettings{Enabled: true, URL: ts.URL, SiteID: site, SiteName: "Home", CertSHA256: info.SHA256},
		f.key, box, "admin"); err != nil {
		t.Fatal(err)
	}
	s := &Syncer{Store: st, Box: box, Log: slog.Default()}

	// No bans yet: an IPv4 list with the placeholder, no IPv6 list.
	if err := s.Sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(f.lists) != 1 {
		t.Fatalf("lists = %+v", f.lists)
	}
	var v4ID string
	for id, l := range f.lists {
		v4ID = id
		if l.Name != "Switchyard bans (IPv4)" || l.Type != "IPV4_ADDRESSES" || len(l.Items) != 1 || l.Items[0].Value != placeholderV4 {
			t.Errorf("empty list = %+v", l)
		}
	}
	if st := s.Status(); st.LastError != "" || len(st.Lists) != 1 || len(st.Lists[0].Policies) != 0 {
		t.Errorf("status = %+v", st)
	}

	// Bans, IPv4 and IPv6; a policy on the console blocks the IPv4 list.
	for _, b := range []string{"203.0.113.9", "198.51.100.0/24", "2001:db8::1"} {
		if _, err := st.AddBan(ctx, b, "test", "manual", 0, 0, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	f.policies = []map[string]any{{"id": "p1", "name": "Drop Switchyard bans", "enabled": true, "action": map[string]any{"type": "BLOCK"},
		"source": map[string]any{"zoneId": "z", "trafficFilter": map[string]any{"type": "IP_ADDRESS",
			"ipAddressFilter": map[string]any{"type": "TRAFFIC_MATCHING_LIST", "matchOpposite": false, "trafficMatchingListId": v4ID}}}}}
	if err := s.Sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	l4 := f.lists[v4ID]
	if fmt.Sprint(l4.Items) != "[{SUBNET 198.51.100.0/24} {IP_ADDRESS 203.0.113.9}]" {
		t.Errorf("IPv4 items = %v", l4.Items)
	}
	if len(f.lists) != 2 {
		t.Fatalf("no IPv6 list: %+v", f.lists)
	}
	stt := s.Status()
	if stt.IPv4 != 2 || stt.IPv6 != 1 || len(stt.Lists) != 2 || len(stt.Lists[0].Policies) != 1 ||
		stt.Lists[0].Policies[0] != (PolicyInfo{Name: "Drop Switchyard bans", Enabled: true, Action: "BLOCK"}) || len(stt.Lists[1].Policies) != 0 {
		t.Errorf("status = %+v", stt)
	}

	// Unchanged: nothing sent. Forced: sent.
	puts := f.puts
	if err := s.Sync(ctx, false); err != nil || f.puts != puts {
		t.Errorf("unchanged sync sent %d updates (%v)", f.puts-puts, err)
	}
	if err := s.Sync(ctx, true); err != nil || f.puts == puts {
		t.Errorf("forced sync sent nothing (%v)", err)
	}

	// Someone deletes the list on the console: it's made again.
	delete(f.lists, v4ID)
	if err := s.Sync(ctx, true); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range f.lists {
		found = found || (l.Type == "IPV4_ADDRESSES" && len(l.Items) == 2)
	}
	if !found {
		t.Errorf("IPv4 list not recreated: %+v", f.lists)
	}

	// Bans lifted: back to the placeholder, list kept.
	bans, _ := st.ListBans(ctx, true, 10)
	for _, b := range bans {
		_ = st.RemoveBan(ctx, b.ID, "admin")
	}
	if err := s.Sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	for _, l := range f.lists {
		if len(l.Items) != 1 || (l.Items[0].Value != placeholderV4 && l.Items[0].Value != placeholderV6) {
			t.Errorf("after lifting bans: %+v", l)
		}
	}

	// A wrong key shows on the status page.
	f.key = "rotated"
	if err := s.Sync(ctx, true); err == nil || !strings.Contains(s.Status().LastError, "API key") {
		t.Errorf("wrong key: %v / %q", err, s.Status().LastError)
	}
}
