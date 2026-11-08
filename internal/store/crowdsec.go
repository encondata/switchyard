package store

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/encondata/switchyard/internal/secrets"
)

// CrowdSecSettings connect Caddy to a CrowdSec Local API as a bouncer
// (spec §3, F6; CPM-32). The bouncer API key is sealed separately.
type CrowdSecSettings struct {
	Enabled bool   `json:"enabled"`
	APIURL  string `json:"api_url"`
	KeySet  bool   `json:"key_set"`
}

const (
	settingCrowdSec    = "crowdsec"
	settingCrowdSecKey = "crowdsec_key"
	crowdSecPurpose    = "crowdsec-bouncer"
)

// CrowdSec returns the CrowdSec settings.
func (s *Store) CrowdSec(ctx context.Context) (CrowdSecSettings, error) {
	var c CrowdSecSettings
	v, err := s.GetSetting(ctx, settingCrowdSec)
	if err != nil {
		return c, err
	}
	if v != "" {
		_ = json.Unmarshal([]byte(v), &c)
	}
	k, err := s.GetSetting(ctx, settingCrowdSecKey)
	c.KeySet = k != ""
	return c, err
}

// SaveCrowdSec stores the settings; an empty key keeps the stored one.
func (s *Store) SaveCrowdSec(ctx context.Context, c CrowdSecSettings, key string, box *secrets.Box, by string) (CrowdSecSettings, error) {
	c.APIURL = strings.TrimSpace(c.APIURL)
	key = strings.TrimSpace(key)
	errs := ValidationError{}
	if c.Enabled || c.APIURL != "" {
		u, err := url.Parse(c.APIURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(c.APIURL, "{}") {
			errs["api_url"] = "the CrowdSec Local API address, e.g. http://crowdsec:8080/"
		}
	}
	if key != "" && (len(key) > 200 || strings.ContainsAny(key, "{}\\\" \r\n")) {
		errs["api_key"] = "that doesn't look like a bouncer key (from `cscli bouncers add cpm`)"
	}
	current, err := s.CrowdSec(ctx)
	if err != nil {
		return c, err
	}
	if c.Enabled && key == "" && !current.KeySet {
		errs["api_key"] = "paste the bouncer key from `cscli bouncers add cpm`"
	}
	if len(errs) > 0 {
		return c, errs
	}
	if key != "" {
		if !box.Ready() {
			return c, ConflictError(secrets.ErrNoKey.Error())
		}
		sealed, err := box.Seal(key, crowdSecPurpose)
		if err != nil {
			return c, err
		}
		if err := s.SetSetting(ctx, settingCrowdSecKey, sealed, by); err != nil {
			return c, err
		}
	}
	c.KeySet = false
	b, _ := json.Marshal(c)
	if err := s.SetSetting(ctx, settingCrowdSec, string(b), by); err != nil {
		return c, err
	}
	return s.CrowdSec(ctx)
}

// CrowdSecKey decrypts the bouncer key ("" if none).
func (s *Store) CrowdSecKey(ctx context.Context, box *secrets.Box) (string, error) {
	sealed, err := s.GetSetting(ctx, settingCrowdSecKey)
	if err != nil || sealed == "" {
		return "", err
	}
	return box.Open(sealed, crowdSecPurpose)
}
