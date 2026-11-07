package geoip

import (
	"path/filepath"
	"testing"

	"github.com/encondata/caddyproxymanager/internal/geoip/geoiptest"
)

func TestCountries(t *testing.T) {
	if !ValidCountry("us") || !ValidCountry("DE") || ValidCountry("XX") || ValidCountry("EU") {
		t.Fatal("ValidCountry wrong")
	}
	cs := Countries()
	if len(cs) < 240 {
		t.Fatalf("only %d countries", len(cs))
	}
	found := false
	for _, c := range cs {
		if c.Code == "GB" && c.Name == "United Kingdom" {
			found = true
		}
	}
	if !found {
		t.Fatal("GB missing or misnamed")
	}
}

func TestLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.mmdb")
	if err := geoiptest.Write(path, map[string]string{"203.0.113.0/24": "AU", "2001:db8::/32": "DE"}); err != nil {
		t.Fatal(err)
	}
	db := &DB{Path: path}
	if !db.Available() {
		t.Fatal("not available")
	}
	if got := db.Country("203.0.113.9"); got != "AU" {
		t.Fatalf("Country = %q", got)
	}
	if got := db.Country("2001:db8::1"); got != "DE" {
		t.Fatalf("Country v6 = %q", got)
	}
	if got := db.Country("198.51.100.1"); got != "" {
		t.Fatalf("unknown = %q", got)
	}
	if (&DB{Path: filepath.Join(t.TempDir(), "none")}).Available() {
		t.Fatal("missing file reported available")
	}
}
