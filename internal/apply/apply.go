// Package apply builds the Caddy config from the database, shows what would
// change, sends it to Caddy and keeps the version history (spec §2,
// CPM-8, CPM-9, CPM-10).
package apply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pmezard/go-difflib/difflib"

	"github.com/encondata/switchyard/internal/compiler"
	"github.com/encondata/switchyard/internal/geoip"
	"github.com/encondata/switchyard/internal/secrets"
	"github.com/encondata/switchyard/internal/store"
)

// Caddy is the part of the admin API the service needs.
type Caddy interface {
	Config(ctx context.Context) ([]byte, error)
	Load(ctx context.Context, config []byte) error
}

// Service applies configs. Applies are serialized.
type Service struct {
	Store    *store.Store
	Caddy    Caddy
	Settings compiler.Settings
	// ConfigFile, if set, receives each successfully applied config so Caddy
	// starts with it after a restart.
	ConfigFile string
	// Box decrypts DNS provider tokens; SecretsDir is where they're written
	// for Caddy (see compiler.Settings.SecretsDir).
	Box        *secrets.Box
	SecretsDir string
	// CaddyFallbackGeoIPDB is the DB-IP file's path as Caddy sees it, used
	// when MaxMind's file (Settings.GeoIPDB) isn't installed.
	CaddyFallbackGeoIPDB string
	// GeoIP is the country database as CPM sees it; country rules compile
	// only when it exists.
	GeoIP *geoip.DB

	mu sync.Mutex
}

// Preview describes the pending change.
type Preview struct {
	// Pending is true when the config built from the database differs from
	// what Caddy is running.
	Pending bool `json:"pending"`
	// Diff is a unified diff from the running config to the new one.
	Diff string `json:"diff"`
	// Drift is true when Caddy's running config isn't the last one CPM
	// applied (someone changed Caddy directly, or Caddy restarted without it).
	Drift      bool   `json:"drift"`
	CaddyError string `json:"caddy_error,omitempty"`
	// Changes counts edits saved since the last successful apply.
	Changes       int                  `json:"changes"`
	LastApplied   *store.ConfigVersion `json:"last_applied,omitempty"`
	CandidateHash string               `json:"candidate_sha256"`
}

// Build compiles the config from the current database state.
func (s *Service) Build(ctx context.Context) ([]byte, error) {
	hosts, err := s.Store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	access, err := s.Store.LoadAccessState(ctx)
	if err != nil {
		return nil, err
	}
	settings := s.Settings
	settings.GeoIPReady = s.GeoIP.Available()
	// Without MaxMind's file, Caddy uses the DB-IP one CPM downloads.
	if p := s.GeoIP.ActivePath(); p != "" && p == s.GeoIP.Fallback && s.CaddyFallbackGeoIPDB != "" {
		settings.GeoIPDB = s.CaddyFallbackGeoIPDB
	}
	return compiler.Compile(settings, hosts, access)
}

// Preview compares the database's config with Caddy's running config.
func (s *Service) Preview(ctx context.Context) (Preview, error) {
	candidate, err := s.Build(ctx)
	if err != nil {
		return Preview{}, err
	}
	p := Preview{CandidateHash: hash(candidate)}
	if last, err := s.Store.LastAppliedConfig(ctx); err == nil {
		last.JSON = ""
		p.LastApplied = &last
	} else if !errors.Is(err, store.ErrNotFound) {
		return Preview{}, err
	}

	running, err := s.Caddy.Config(ctx)
	if err != nil {
		p.CaddyError = err.Error()
		p.Pending = true
		p.Diff = unifiedDiff("", string(candidate), "running (unknown)")
		return p, nil
	}
	runningNorm, err := Normalize(running)
	if err != nil {
		return Preview{}, fmt.Errorf("reading Caddy's config: %w", err)
	}
	p.Pending = !bytes.Equal(runningNorm, candidate)
	if p.Pending {
		p.Diff = unifiedDiff(string(runningNorm), string(candidate), "running")
	}
	if last, err := s.Store.LastAppliedConfig(ctx); err == nil {
		p.Drift = !SameIgnoringBans(runningNorm, []byte(last.JSON))
		if p.Pending {
			p.Changes, _ = s.Store.ChangesSince(ctx, last.AppliedAt)
		}
	}
	if p.Pending && p.Changes == 0 {
		p.Changes = 1
	}
	return p, nil
}

// VersionDiff is a unified diff from the successful version before n to n.
func (s *Service) VersionDiff(ctx context.Context, n int64) (string, int64, error) {
	v, err := s.Store.GetConfigVersion(ctx, n)
	if err != nil {
		return "", 0, err
	}
	prev, err := s.Store.PreviousAppliedConfig(ctx, n)
	if errors.Is(err, store.ErrNotFound) {
		return unifiedDiff("", v.JSON, "(nothing)"), 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	a, _ := Normalize([]byte(prev.JSON))
	b, _ := Normalize([]byte(v.JSON))
	return unifiedDiff(string(a), string(b), fmt.Sprintf("version %d", prev.N)), prev.N, nil
}

// SameIgnoringBans compares two configs, ignoring the ban lists, which CPM
// updates in place between full applies (so they aren't drift).
func SameIgnoringBans(a, b []byte) bool {
	na, err1 := stripBans(a)
	nb, err2 := stripBans(b)
	return err1 == nil && err2 == nil && bytes.Equal(na, nb)
}

func stripBans(raw []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			if id, _ := x["@id"].(string); strings.HasPrefix(id, "cpm_banlist_") {
				x["match"] = nil
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(v)
	return json.Marshal(v)
}

// Patcher is the admin API call for in-place updates.
type Patcher interface {
	Patch(ctx context.Context, path string, value any) error
}

// PushBans updates the ban list in the running Caddy config by ID, without
// a full reload (spec F6: bans reach every host within seconds), and saves
// the result for Caddy restarts.
func (s *Service) PushBans(ctx context.Context) error {
	p, ok := s.Caddy.(Patcher)
	if !ok {
		return errors.New("this Caddy client can't patch the config")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bans, err := s.Store.ActiveBanRanges(ctx)
	if err != nil {
		return err
	}
	never, err := s.Store.ListNeverBan(ctx)
	if err != nil {
		return err
	}
	var neverRanges []string
	for _, n := range never {
		neverRanges = append(neverRanges, n.CIDR)
	}
	match := compiler.BanMatch(bans, neverRanges)
	for _, srv := range []string{"http", "https"} {
		if err := p.Patch(ctx, "/id/"+compiler.BanListID(srv)+"/match", match); err != nil {
			return fmt.Errorf("updating %s ban list (apply the config once if this is a new install): %w", srv, err)
		}
	}
	if s.ConfigFile != "" {
		if running, err := s.Caddy.Config(ctx); err == nil {
			_ = writeAtomic(s.ConfigFile, running)
		}
	}
	return nil
}

// Apply builds the config from the database and loads it into Caddy.
func (s *Service) Apply(ctx context.Context, username, note string) (store.ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate, err := s.Build(ctx)
	if err != nil {
		return store.ConfigVersion{}, err
	}
	return s.load(ctx, candidate, username, note)
}

// Rollback re-applies an earlier successful version. The database (hosts)
// is not changed, so the UI will show pending changes afterwards.
func (s *Service) Rollback(ctx context.Context, n int64, username string) (store.ConfigVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.Store.GetConfigVersion(ctx, n)
	if err != nil {
		return store.ConfigVersion{}, err
	}
	if v.Result != "ok" {
		return store.ConfigVersion{}, fmt.Errorf("version %d failed when it was applied; pick a version that worked", n)
	}
	return s.load(ctx, []byte(v.JSON), username, fmt.Sprintf("rollback to version %d", n))
}

// Retry makes Caddy reload the config it's running, which restarts
// certificate management so failed certificates are tried again now
// instead of after Caddy's backoff.
func (s *Service) Retry(ctx context.Context) error {
	r, ok := s.Caddy.(interface {
		Reload(ctx context.Context, config []byte) error
	})
	if !ok {
		return errors.New("this Caddy client can't force a reload")
	}
	if err := s.SyncSecrets(ctx); err != nil {
		return err
	}
	running, err := s.Caddy.Config(ctx)
	if err != nil {
		return err
	}
	return r.Reload(ctx, running)
}

// SyncSecrets writes each DNS provider's token to SecretsDir (mode 0600,
// readable by Caddy, which runs as the same user) and removes files for
// providers that no longer exist.
func (s *Service) SyncSecrets(ctx context.Context) error {
	if s.SecretsDir == "" {
		return nil
	}
	tokens := map[int64]string{}
	if s.Box.Ready() {
		var err error
		if tokens, err = s.Store.DNSTokens(ctx, s.Box); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(s.SecretsDir, 0o700); err != nil {
		return err
	}
	keep := map[string]bool{}
	for id, tok := range tokens {
		path := compiler.DNSTokenFile(s.SecretsDir, id)
		keep[filepath.Base(path)] = true
		if err := writeFile(path, []byte(tok), 0o600); err != nil {
			return err
		}
	}
	if s.Box.Ready() {
		key, err := s.Store.CrowdSecKey(ctx, s.Box)
		if err != nil {
			return err
		}
		path := compiler.CrowdSecKeyFile(s.SecretsDir)
		if key != "" {
			keep[filepath.Base(path)] = true
			if err := writeFile(path, []byte(key), 0o600); err != nil {
				return err
			}
		} else {
			_ = os.Remove(path)
		}
	}
	entries, err := os.ReadDir(s.SecretsDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "dns-") && strings.HasSuffix(e.Name(), ".token") && !keep[e.Name()] {
			_ = os.Remove(filepath.Join(s.SecretsDir, e.Name()))
		}
	}
	return nil
}

func (s *Service) load(ctx context.Context, config []byte, username, note string) (store.ConfigVersion, error) {
	if err := s.SyncSecrets(ctx); err != nil {
		return store.ConfigVersion{}, fmt.Errorf("writing DNS provider tokens for Caddy: %w", err)
	}
	v := store.ConfigVersion{
		JSON: string(config), SHA256: hash(config), AppliedBy: username,
		AppliedAt: time.Now().UTC(), Result: "ok", Note: note,
	}
	loadErr := s.Caddy.Load(ctx, config)
	if loadErr != nil {
		v.Result = "failed"
		v.Error = loadErr.Error()
	}
	n, err := s.Store.AddConfigVersion(ctx, v)
	if err != nil {
		return v, err
	}
	v.N = n
	if loadErr != nil {
		return v, loadErr
	}
	if s.ConfigFile != "" {
		if err := writeAtomic(s.ConfigFile, config); err != nil {
			return v, fmt.Errorf("config applied, but saving it for Caddy restarts failed: %w", err)
		}
	}
	return v, nil
}

// Normalize re-encodes JSON the way the compiler does (sorted keys, two-space
// indent), so configs from Caddy and from the compiler compare byte for byte.
func Normalize(raw []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func unifiedDiff(from, to, fromName string) string {
	d, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(from), B: difflib.SplitLines(to),
		FromFile: fromName, ToFile: "new", Context: 3,
	})
	return d
}

func writeAtomic(path string, data []byte) error { return writeFile(path, data, 0o640) }

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".caddy-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
