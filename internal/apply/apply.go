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
	"sync"
	"time"

	"github.com/pmezard/go-difflib/difflib"

	"github.com/encondata/caddyproxymanager/internal/compiler"
	"github.com/encondata/caddyproxymanager/internal/store"
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
	Drift         bool                 `json:"drift"`
	CaddyError    string               `json:"caddy_error,omitempty"`
	LastApplied   *store.ConfigVersion `json:"last_applied,omitempty"`
	CandidateHash string               `json:"candidate_sha256"`
}

// Build compiles the config from the current database state.
func (s *Service) Build(ctx context.Context) ([]byte, error) {
	hosts, err := s.Store.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	return compiler.Compile(s.Settings, hosts)
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
	if p.LastApplied != nil {
		p.Drift = hash(runningNorm) != p.LastApplied.SHA256
	}
	return p, nil
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

func (s *Service) load(ctx context.Context, config []byte, username, note string) (store.ConfigVersion, error) {
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

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".caddy-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
