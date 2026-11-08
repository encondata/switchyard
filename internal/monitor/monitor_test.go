package monitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/encondata/switchyard/internal/apply"
	"github.com/encondata/switchyard/internal/compiler"
	"github.com/encondata/switchyard/internal/store"
)

type fakeCaddy struct {
	running []byte
	down    bool
}

func (f *fakeCaddy) Config(context.Context) ([]byte, error) {
	if f.down {
		return nil, errors.New("connection refused")
	}
	return f.running, nil
}
func (f *fakeCaddy) Load(_ context.Context, b []byte) error { f.running = b; return nil }

type recorder struct{ got []store.Alert }

func (r *recorder) Notify(_ context.Context, a store.Alert) { r.got = append(r.got, a) }

func setup(t *testing.T) (*Monitor, *apply.Service, *fakeCaddy, *store.Store, *recorder) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "cpm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fc := &fakeCaddy{running: []byte(`{}`)}
	svc := &apply.Service{Store: st, Caddy: fc, Settings: compiler.Settings{AdminListen: "unix//x.sock"}}
	rec := &recorder{}
	logs := t.TempDir()
	m := &Monitor{
		Store: st, Caddy: fc, CaddyDataDir: t.TempDir(), TLSLogFile: filepath.Join(logs, "tls.log"),
		LogDir: logs, Notifier: rec, Log: slog.Default(),
	}
	return m, svc, fc, st, rec
}

func openAlerts(t *testing.T, st *store.Store) map[string]string {
	t.Helper()
	as, err := st.ListAlerts(context.Background(), true, 100)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, a := range as {
		out[a.Kind+":"+a.Subject] = a.Message
	}
	return out
}

func TestDriftAndReachability(t *testing.T) {
	ctx := context.Background()
	m, svc, fc, st, rec := setup(t)
	if _, err := svc.Apply(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := m.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if s := m.Snapshot(); !s.CaddyReachable || s.Drift || s.LastApply == nil {
		t.Fatalf("snapshot = %+v", s)
	}

	fc.running = []byte(`{"apps":{}}`)
	_ = m.Check(ctx)
	if _, ok := openAlerts(t, st)["drift:caddy"]; !ok || !m.Snapshot().Drift {
		t.Fatal("drift not alerted")
	}
	_ = m.Check(ctx) // still drifting: no second notification
	if len(rec.got) != 1 {
		t.Fatalf("notifications = %d, want 1", len(rec.got))
	}

	fc.down = true
	_ = m.Check(ctx)
	if _, ok := openAlerts(t, st)["caddy_unreachable:caddy"]; !ok {
		t.Fatal("unreachable not alerted")
	}

	fc.down = false
	if _, err := svc.Apply(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	_ = m.Check(ctx)
	if open := openAlerts(t, st); len(open) != 0 {
		t.Fatalf("alerts should resolve: %v", open)
	}
}

func TestCertErrorsFromLog(t *testing.T) {
	ctx := context.Background()
	m, _, _, st, _ := setup(t)
	if _, err := st.SaveHost(ctx, store.Host{
		Type: store.Host404, Enabled: true, Domains: []string{"fail.example.com"}, TLSMode: store.TLSAuto,
	}, "admin"); err != nil {
		t.Fatal(err)
	}
	ts := float64(time.Now().Unix())
	line := func(level, msg, ident, errMsg string) string {
		return fmt.Sprintf(`{"level":%q,"ts":%f,"logger":"tls.obtain","msg":%q,"identifier":%q,"error":%q}`+"\n", level, ts, msg, ident, errMsg)
	}
	write := func(s string) {
		f, err := os.OpenFile(m.TLSLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(s)
		_ = f.Close()
	}
	write(`not json` + "\n" + line("error", "could not get certificate from issuer", "fail.example.com", "DNS problem: NXDOMAIN"))
	_ = m.Check(ctx)
	rows, _ := m.Certs(ctx)
	if len(rows) != 1 || rows[0].LastError == nil || rows[0].LastError.Message != "DNS problem: NXDOMAIN" {
		t.Fatalf("rows = %+v", rows)
	}
	if msg, ok := openAlerts(t, st)["cert_failed:fail.example.com"]; !ok || msg == "" {
		t.Fatal("cert failure not alerted")
	}

	write(line("info", "certificate obtained successfully", "fail.example.com", ""))
	_ = m.Check(ctx)
	if rows, _ = m.Certs(ctx); rows[0].LastError != nil {
		t.Fatal("success should clear the error")
	}
	if _, ok := openAlerts(t, st)["cert_failed:fail.example.com"]; ok {
		t.Fatal("cert alert should resolve")
	}
}
