package store

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/encondata/switchyard/internal/secrets"
)

// UniFiSettings sync the ban list into a UniFi console's firewall, as
// "traffic matching lists" a firewall policy blocks. The console's API key
// is sealed separately.
type UniFiSettings struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`       // the console, e.g. https://192.168.1.1
	SiteID   string `json:"site_id"`   // UUID from the console's site list
	SiteName string `json:"site_name"` // for display
	ListName string `json:"list_name"` // " (IPv4)" / " (IPv6)" is added
	// CertSHA256 pins the console's certificate (they ship a self-signed
	// one); empty means normal certificate checks.
	CertSHA256 string `json:"cert_sha256"`
	KeySet     bool   `json:"key_set"`
}

// DefaultUniFi starts off, with the lists' default name.
var DefaultUniFi = UniFiSettings{ListName: "Switchyard bans"}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	settingUniFi      = "unifi"
	settingUniFiKey   = "unifi_key"
	settingUniFiState = "unifi_state"
	unifiPurpose      = "unifi-api-key"
)

// UniFi returns the UniFi settings.
func (s *Store) UniFi(ctx context.Context) (UniFiSettings, error) {
	u := DefaultUniFi
	v, err := s.GetSetting(ctx, settingUniFi)
	if err != nil {
		return u, err
	}
	if v != "" {
		_ = json.Unmarshal([]byte(v), &u)
	}
	k, err := s.GetSetting(ctx, settingUniFiKey)
	u.KeySet = k != ""
	return u, err
}

// SaveUniFi stores the settings; an empty key keeps the stored one.
func (s *Store) SaveUniFi(ctx context.Context, u UniFiSettings, key string, box *secrets.Box, by string) (UniFiSettings, error) {
	u.URL = strings.TrimRight(strings.TrimSpace(u.URL), "/")
	if u.URL != "" && !strings.Contains(u.URL, "://") {
		u.URL = "https://" + u.URL
	}
	u.ListName = strings.TrimSpace(u.ListName)
	if u.ListName == "" {
		u.ListName = DefaultUniFi.ListName
	}
	key = strings.TrimSpace(key)
	errs := ValidationError{}
	if u.Enabled || u.URL != "" {
		p, err := url.Parse(u.URL)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" || (p.Path != "" && p.Path != "/") {
			errs["url"] = "the console's address, e.g. https://192.168.1.1"
		}
	}
	u.CertSHA256 = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(u.CertSHA256), ":", ""))
	if u.CertSHA256 != "" && !sha256Hex.MatchString(u.CertSHA256) {
		errs["cert_sha256"] = "a SHA-256 fingerprint (64 hex digits)"
	}
	if len(u.ListName) > 100 {
		errs["list_name"] = "keep it under 100 characters"
	}
	if key != "" && (len(key) > 500 || strings.ContainsAny(key, " \r\n\"")) {
		errs["api_key"] = "that doesn't look like a UniFi API key"
	}
	current, err := s.UniFi(ctx)
	if err != nil {
		return u, err
	}
	if u.Enabled && key == "" && !current.KeySet {
		errs["api_key"] = "paste an API key from the console (Settings, Control Plane, Integrations)"
	}
	if u.Enabled && u.SiteID == "" {
		errs["site_id"] = "choose the site (Check connection lists them)"
	}
	if len(errs) > 0 {
		return u, errs
	}
	if key != "" {
		if !box.Ready() {
			return u, ConflictError(secrets.ErrNoKey.Error())
		}
		sealed, err := box.Seal(key, unifiPurpose)
		if err != nil {
			return u, err
		}
		if err := s.SetSetting(ctx, settingUniFiKey, sealed, by); err != nil {
			return u, err
		}
	}
	// A different console or site has different lists.
	if current.URL != u.URL || current.SiteID != u.SiteID {
		_ = s.SaveUniFiState(ctx, UniFiState{})
	}
	u.KeySet = false
	b, _ := json.Marshal(u)
	if err := s.SetSetting(ctx, settingUniFi, string(b), by); err != nil {
		return u, err
	}
	return s.UniFi(ctx)
}

// UniFiKey decrypts the console API key ("" if none).
func (s *Store) UniFiKey(ctx context.Context, box *secrets.Box) (string, error) {
	sealed, err := s.GetSetting(ctx, settingUniFiKey)
	if err != nil || sealed == "" {
		return "", err
	}
	return box.Open(sealed, unifiPurpose)
}

// UniFiState is what the sync remembers between runs: the IDs of the lists
// it made on the console.
type UniFiState struct {
	IPv4ListID string `json:"ipv4_list_id"`
	IPv6ListID string `json:"ipv6_list_id"`
}

// UniFiState returns the sync's remembered list IDs.
func (s *Store) UniFiState(ctx context.Context) (UniFiState, error) {
	var st UniFiState
	v, err := s.GetSetting(ctx, settingUniFiState)
	if err == nil && v != "" {
		_ = json.Unmarshal([]byte(v), &st)
	}
	return st, err
}

// SaveUniFiState records the list IDs. It's the sync's own bookkeeping,
// not someone's change, so it isn't audited.
func (s *Store) SaveUniFiState(ctx context.Context, st UniFiState) error {
	b, _ := json.Marshal(st)
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, settingUniFiState, string(b))
	return err
}
