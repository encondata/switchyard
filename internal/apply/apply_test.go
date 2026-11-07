package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encondata/caddyproxymanager/internal/compiler"
	"github.com/encondata/caddyproxymanager/internal/store"
)

// fakeCaddy stores whatever it's loaded, compacted like Caddy returns it.
type fakeCaddy struct {
	running []byte
	reject  string
}

func (f *fakeCaddy) Config(context.Context) ([]byte, error) { return f.running, nil }

func (f *fakeCaddy) Load(_ context.Context, cfg []byte) error {
	if f.reject != "" {
		return errors.New(f.reject)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, cfg); err != nil {
		return err
	}
	f.running = buf.Bytes()
	return nil
}

func setup(t *testing.T) (*Service, *fakeCaddy, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fc := &fakeCaddy{running: []byte(`{"admin":{"listen":"unix//x.sock"}}`)}
	svc := &Service{
		Store: st, Caddy: fc,
		Settings:   compiler.Settings{AdminListen: "unix//x.sock"},
		ConfigFile: filepath.Join(t.TempDir(), "caddy.json"),
	}
	return svc, fc, st
}

func addHost(t *testing.T, st *store.Store, domain string) store.Host {
	t.Helper()
	h, err := st.SaveHost(context.Background(), store.Host{
		Type: store.HostProxy, Enabled: true, Domains: []string{domain}, TLSMode: store.TLSOff,
		Upstreams: []store.Upstream{{Host: "app", Port: 8080}},
	}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestApplyFlow(t *testing.T) {
	ctx := context.Background()
	svc, fc, st := setup(t)

	p, err := svc.Preview(ctx)
	if err != nil || !p.Pending || p.Drift {
		t.Fatalf("initial preview = %+v, %v; want pending, no drift (nothing applied yet)", p, err)
	}

	addHost(t, st, "app.localhost")
	p, _ = svc.Preview(ctx)
	if !strings.Contains(p.Diff, `+          "routes": [`) && !strings.Contains(p.Diff, "app.localhost") {
		t.Fatalf("diff doesn't mention the new host:\n%s", p.Diff)
	}

	v, err := svc.Apply(ctx, "admin", "")
	if err != nil || v.Result != "ok" || v.N == 0 {
		t.Fatalf("apply = %+v, %v", v, err)
	}
	saved, err := os.ReadFile(svc.ConfigFile)
	if err != nil || !strings.Contains(string(saved), "app.localhost") {
		t.Fatalf("config file not written: %v", err)
	}

	p, _ = svc.Preview(ctx)
	if p.Pending || p.Drift || p.Diff != "" {
		t.Fatalf("after apply preview = %+v; want nothing pending", p)
	}

	// Someone changes Caddy behind CPM's back.
	fc.running = []byte(`{"apps":{}}`)
	p, _ = svc.Preview(ctx)
	if !p.Drift || !p.Pending {
		t.Fatalf("drift not detected: %+v", p)
	}
}

func TestApplyRejected(t *testing.T) {
	ctx := context.Background()
	svc, fc, st := setup(t)
	addHost(t, st, "app.localhost")
	fc.reject = "loading new config: bad route"

	v, err := svc.Apply(ctx, "admin", "")
	if err == nil || v.Result != "failed" || !strings.Contains(v.Error, "bad route") {
		t.Fatalf("apply = %+v, %v; want a recorded failure", v, err)
	}
	if _, err := os.Stat(svc.ConfigFile); !os.IsNotExist(err) {
		t.Fatal("config file written for a failed apply")
	}
	if _, err := svc.Rollback(ctx, v.N, "admin"); err == nil {
		t.Fatal("rollback to a failed version should be refused")
	}
}

func TestRollback(t *testing.T) {
	ctx := context.Background()
	svc, fc, st := setup(t)
	addHost(t, st, "one.localhost")
	v1, _ := svc.Apply(ctx, "admin", "")
	addHost(t, st, "two.localhost")
	if _, err := svc.Apply(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fc.running), "two.localhost") {
		t.Fatal("second apply not loaded")
	}

	v3, err := svc.Rollback(ctx, v1.N, "admin")
	if err != nil || !strings.Contains(v3.Note, "rollback") {
		t.Fatalf("rollback = %+v, %v", v3, err)
	}
	if strings.Contains(string(fc.running), "two.localhost") {
		t.Fatal("rollback didn't restore version 1")
	}
	// The database still has both hosts, so the change shows as pending.
	if p, _ := svc.Preview(ctx); !p.Pending || p.Drift {
		t.Fatalf("after rollback preview = %+v; want pending, no drift", p)
	}
}

func TestVersionDiff(t *testing.T) {
	ctx := context.Background()
	svc, _, st := setup(t)
	addHost(t, st, "one.localhost")
	v1, _ := svc.Apply(ctx, "admin", "")
	addHost(t, st, "two.localhost")
	v2, _ := svc.Apply(ctx, "admin", "")
	diff, prev, err := svc.VersionDiff(ctx, v2.N)
	if err != nil || prev != v1.N || !strings.Contains(diff, "+") || !strings.Contains(diff, "two.localhost") || strings.Contains(diff, "+          \"one.localhost\"") {
		t.Fatalf("diff v%d (prev %d, err %v):\n%s", v2.N, prev, err, diff)
	}
	first, prev, _ := svc.VersionDiff(ctx, v1.N)
	if prev != 0 || !strings.Contains(first, "one.localhost") {
		t.Fatalf("first version diff (prev %d):\n%s", prev, first)
	}
}
