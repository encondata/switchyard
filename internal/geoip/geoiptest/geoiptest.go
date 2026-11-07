// Package geoiptest writes small GeoIP country databases for tests.
package geoiptest

import (
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// Write creates a GeoIP2-Country-style database mapping CIDRs to ISO codes.
func Write(path string, networks map[string]string) error {
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoIP2-Country", RecordSize: 24, IncludeReservedNetworks: true})
	if err != nil {
		return err
	}
	for cidr, code := range networks {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		rec := mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(code)}}
		if err := w.Insert(n, rec); err != nil {
			return err
		}
	}
	f, err := os.Create(path) //nolint:gosec // test helper
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = w.WriteTo(f)
	return err
}
