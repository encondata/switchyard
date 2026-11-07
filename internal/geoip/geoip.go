// Package geoip looks up the country of an IP address in a MaxMind
// GeoLite2-Country database (spec F4, F5) and knows the ISO country codes.
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

// DB reads a GeoLite2/GeoIP2 Country database, reopening it when the file
// changes (geoipupdate replaces it weekly).
type DB struct {
	Path string

	mu     sync.Mutex
	reader *maxminddb.Reader
	mtime  time.Time
	nextCh time.Time
}

// ModTime returns when the database file was last updated, or false if it
// isn't there.
func (d *DB) ModTime() (time.Time, bool) {
	if d == nil || d.Path == "" {
		return time.Time{}, false
	}
	info, err := os.Stat(d.Path)
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

// Available reports whether the database file exists.
func (d *DB) Available() bool {
	_, ok := d.ModTime()
	return ok
}

func (d *DB) open() *maxminddb.Reader {
	now := time.Now()
	if d.reader != nil && now.Before(d.nextCh) {
		return d.reader
	}
	d.nextCh = now.Add(time.Minute)
	mt, ok := d.ModTime()
	if !ok {
		return d.reader
	}
	if d.reader != nil && mt.Equal(d.mtime) {
		return d.reader
	}
	r, err := maxminddb.Open(d.Path)
	if err != nil {
		return d.reader
	}
	if d.reader != nil {
		_ = d.reader.Close()
	}
	d.reader, d.mtime = r, mt
	return r
}

// Country returns the ISO code for ip, or "" if unknown.
func (d *DB) Country(ip string) string {
	if d == nil || d.Path == "" {
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
