// Package geoip looks up the country of an IP address (spec F4, F5) in a
// MaxMind GeoLite2-Country database if one is installed, or else in DB-IP's
// free IP-to-Country Lite database, which CPM downloads itself (see
// Updater). It also knows the ISO country codes.
package geoip

import (
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// Country is an ISO 3166-1 alpha-2 code with its English name.
type Country struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

var (
	countriesOnce sync.Once
	countries     []Country
	countrySet    map[string]bool
)

func loadCountries() {
	countrySet = map[string]bool{}
	names := display.English.Regions()
	for a := 'A'; a <= 'Z'; a++ {
		for b := 'A'; b <= 'Z'; b++ {
			code := string([]rune{a, b})
			r, err := language.ParseRegion(code)
			if err != nil || !r.IsCountry() || r.String() != code {
				continue
			}
			countrySet[code] = true
			countries = append(countries, Country{Code: code, Name: names.Name(r)})
		}
	}
	sort.Slice(countries, func(i, j int) bool { return countries[i].Name < countries[j].Name })
}

// Countries lists every ISO country, sorted by name.
func Countries() []Country {
	countriesOnce.Do(loadCountries)
	return countries
}

// ValidCountry reports whether code is an ISO 3166-1 alpha-2 country code.
func ValidCountry(code string) bool {
	countriesOnce.Do(loadCountries)
	return countrySet[strings.ToUpper(code)]
}

// DB reads a country database, reopening it when the file changes
// (geoipupdate and the DB-IP updater replace it in place). Path is the
// MaxMind GeoLite2 file; Fallback, used when Path doesn't exist, is the
// DB-IP file.
type DB struct {
	Path     string
	Fallback string

	mu     sync.Mutex
	reader *maxminddb.Reader
	path   string
	mtime  time.Time
	nextCh time.Time
}

// ActivePath is the database file in use, or "" if none is installed.
func (d *DB) ActivePath() string {
	if d == nil {
		return ""
	}
	for _, p := range []string{d.Path, d.Fallback} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ModTime returns when the database file in use was last updated, or false
// if none is installed.
func (d *DB) ModTime() (time.Time, bool) {
	p := d.ActivePath()
	if p == "" {
		return time.Time{}, false
	}
	info, err := os.Stat(p)
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

// Available reports whether a database file exists.
func (d *DB) Available() bool {
	return d.ActivePath() != ""
}

// Source names who made the database in use ("DB-IP" or "MaxMind"), or ""
// if none is installed. DB-IP's free data must be credited where shown.
func (d *DB) Source() string {
	if d == nil {
		return ""
	}
	d.mu.Lock()
	r := d.open()
	d.mu.Unlock()
	if r == nil {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(r.Metadata.DatabaseType), "DBIP") {
		return "DB-IP"
	}
	return "MaxMind"
}

func (d *DB) open() *maxminddb.Reader {
	now := time.Now()
	if d.reader != nil && now.Before(d.nextCh) {
		return d.reader
	}
	d.nextCh = now.Add(time.Minute)
	p := d.ActivePath()
	if p == "" {
		return d.reader
	}
	info, err := os.Stat(p)
	if err != nil {
		return d.reader
	}
	if d.reader != nil && p == d.path && info.ModTime().Equal(d.mtime) {
		return d.reader
	}
	r, err := maxminddb.Open(p)
	if err != nil {
		return d.reader
	}
	if d.reader != nil {
		_ = d.reader.Close()
	}
	d.reader, d.path, d.mtime = r, p, info.ModTime()
	return r
}

// LocalNetwork is the "country" of private, loopback and other non-public
// addresses, which no database can place.
const LocalNetwork = "LAN"

// Locate is Country, except that private and other non-public addresses
// give LocalNetwork instead of "". It's what traffic stats record.
func (d *DB) Locate(ip string) string {
	if addr, err := netip.ParseAddr(ip); err == nil {
		a := addr.Unmap()
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || cgnat.Contains(a) {
			return LocalNetwork
		}
	}
	return d.Country(ip)
}

// cgnat is carrier-grade NAT space (RFC 6598), also never public.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Country returns the ISO code for ip, or "" if unknown.
func (d *DB) Country(ip string) string {
	if d == nil {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	d.mu.Lock()
	r := d.open()
	d.mu.Unlock()
	if r == nil {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.Lookup(addr.Unmap()).Decode(&rec); err != nil {
		return ""
	}
	return rec.Country.ISOCode
}
