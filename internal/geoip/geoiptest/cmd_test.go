package geoiptest

import (
	"os"
	"testing"
)

// TestWriteFile writes a database to $CPM_WRITE_TEST_MMDB, for manual
// checks against Caddy. Skipped otherwise.
func TestWriteFile(t *testing.T) {
	path := os.Getenv("CPM_WRITE_TEST_MMDB")
	if path == "" {
		t.Skip("set CPM_WRITE_TEST_MMDB to write a test database")
	}
	if err := Write(path, map[string]string{"172.16.0.0/12": "US", "203.0.113.0/24": "RU"}); err != nil {
		t.Fatal(err)
	}
}
