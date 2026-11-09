package apply

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Delete removes the object with this @id from the running config, as
// Caddy's DELETE /id/<id> does.
func (f *fakeCaddy) Delete(_ context.Context, path string) error {
	id := strings.TrimPrefix(path, "/id/")
	var v any
	if err := json.Unmarshal(f.running, &v); err != nil {
		return err
	}
	var walk func(any) any
	walk = func(n any) any {
		switch x := n.(type) {
		case map[string]any:
			for k, c := range x {
				x[k] = walk(c)
			}
		case []any:
			out := x[:0]
			for _, c := range x {
				if m, ok := c.(map[string]any); ok && m["@id"] == id {
					continue
				}
				out = append(out, walk(c))
			}
			return out
		}
		return n
	}
	f.running, _ = json.Marshal(walk(v))
	return nil
}

func TestHoldRelease(t *testing.T) {
	ctx := context.Background()
	svc, fc, st := setup(t)
	h := addHost(t, st, "new.example.com")
	until := time.Now().Add(time.Hour)
	h.HoldUntil = &until
	if _, err := st.SaveHost(ctx, h, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Apply(ctx, "admin", "with hold"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fc.running), "cpm_hold_") {
		t.Fatal("decoy not in the running config")
	}
	// Not over yet: nothing released.
	if n, err := svc.ReleaseHolds(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("early release = %d, %v", n, err)
	}
	// Stage an unrelated change: releasing must not apply it.
	other := addHost(t, st, "staged.example.com")

	if n, err := svc.ReleaseHolds(ctx, until.Add(time.Second)); err != nil || n != 1 {
		t.Fatalf("release = %d, %v", n, err)
	}
	if strings.Contains(string(fc.running), "cpm_hold_") {
		t.Error("decoy still running")
	}
	if strings.Contains(string(fc.running), "staged.example.com") {
		t.Error("release applied an unrelated staged change")
	}
	if got, _ := st.GetHost(ctx, h.ID); got.HoldUntil != nil {
		t.Error("hold not cleared")
	}
	saved, _ := os.ReadFile(svc.ConfigFile)
	if strings.Contains(string(saved), "cpm_hold_") {
		t.Error("saved config (for Caddy restarts) still has the decoy")
	}
	p, err := svc.Preview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.Drift {
		t.Error("releasing in place counts as drift")
	}
	if !p.Pending || !strings.Contains(p.Diff, "staged.example.com") || strings.Contains(p.Diff, "cpm_hold_") {
		t.Errorf("pending should be just the staged host:\n%s", p.Diff)
	}
	_ = other

	// Release now, on a host that was never applied with a decoy: fine.
	h2 := addHost(t, st, "later.example.com")
	h2.HoldUntil = &until
	_, _ = st.SaveHost(ctx, h2, "admin")
	if err := svc.ReleaseHost(ctx, h2.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetHost(ctx, h2.ID); got.HoldUntil != nil {
		t.Error("release now didn't clear the hold")
	}
}
