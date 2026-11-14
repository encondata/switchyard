package purelymail

import (
	"context"
	"errors"
	"testing"

	"github.com/encondata/switchyard/internal/cloudflare"
)

const proof = "purelymail_ownership_proof=abc123"

func mx(id, host string, prio int) cloudflare.Record {
	return cloudflare.Record{ID: id, Type: "MX", Name: "example.com", Content: host, Priority: &prio}
}

func txt(id, name, v string) cloudflare.Record {
	return cloudflare.Record{ID: id, Type: "TXT", Name: name, Content: v}
}

func cname(id, name, target string, proxied bool) cloudflare.Record {
	return cloudflare.Record{ID: id, Type: "CNAME", Name: name, Content: target, Proxied: proxied}
}

func byKey(items []Item) map[string]Item {
	m := map[string]Item{}
	for _, it := range items {
		m[it.Key] = it
	}
	return m
}

func complete() []cloudflare.Record {
	return []cloudflare.Record{
		mx("1", "mailserver.purelymail.com.", 50),
		txt("2", "example.com", `"v=spf1 include:_spf.purelymail.com ~all"`),
		txt("3", "example.com", `"`+proof+`"`),
		cname("4", "purelymail1._domainkey.example.com", "key1.dkimroot.purelymail.com", false),
		cname("5", "purelymail2._domainkey.example.com", "KEY2.dkimroot.purelymail.com", false),
		cname("6", "purelymail3._domainkey.example.com", "key3.dkimroot.purelymail.com", false),
		cname("7", "_dmarc.example.com", "dmarcroot.purelymail.com", false),
		// Unrelated records are ignored.
		{ID: "8", Type: "A", Name: "www.example.com", Content: "192.0.2.1"},
		txt("9", "example.com", "google-site-verification=xyz"),
	}
}

func TestRecords(t *testing.T) {
	ws := Records("Example.com.", proof)
	if len(ws) != 7 {
		t.Fatalf("got %d records", len(ws))
	}
	m := map[string]Want{}
	for _, w := range ws {
		m[w.Key] = w
	}
	if w := m["mx"]; w.Name != "example.com" || w.Content != MXHost || w.Priority != 50 {
		t.Errorf("mx = %+v", w)
	}
	if w := m["dkim2"]; w.Type != "CNAME" || w.Name != "purelymail2._domainkey.example.com" || w.Content != "key2.dkimroot.purelymail.com" {
		t.Errorf("dkim2 = %+v", w)
	}
	if w := m["dmarc"]; w.Name != "_dmarc.example.com" || w.Content != "dmarcroot.purelymail.com" {
		t.Errorf("dmarc = %+v", w)
	}
}

func TestPlanEmptyZone(t *testing.T) {
	items := Plan("example.com", proof, nil)
	for _, it := range items {
		if it.State != StateMissing {
			t.Errorf("%s: state %s", it.Key, it.State)
		}
	}
	if Status(items) != "incomplete" {
		t.Errorf("status %s", Status(items))
	}
}

func TestPlanComplete(t *testing.T) {
	items := Plan("example.com", proof, complete())
	for _, it := range items {
		if it.State != StateOK || it.Present == nil {
			t.Errorf("%s: state %s, %+v", it.Key, it.State, it)
		}
	}
	if Status(items) != StateOK {
		t.Errorf("status %s", Status(items))
	}
}

func TestPlanNoOwnership(t *testing.T) {
	m := byKey(Plan("example.com", "", complete()))
	if m["ownership"].State != StateNeedsValue {
		t.Errorf("ownership = %+v", m["ownership"])
	}
}

func TestPlanConflicts(t *testing.T) {
	recs := []cloudflare.Record{
		mx("1", "mailserver.purelymail.com", 50),
		mx("2", "aspmx.l.google.com", 1),
		txt("3", "example.com", `"v=spf1 include:_spf.google.com ~all"`),
		txt("4", "example.com", "purelymail_ownership_proof=oldaccount"),
		cname("5", "purelymail1._domainkey.example.com", "key1.dkimroot.purelymail.com", true), // proxied
		txt("6", "purelymail2._domainkey.example.com", "v=DKIM1; k=rsa; p=..."),
		txt("7", "_dmarc.example.com", "v=DMARC1; p=none"),
	}
	m := byKey(Plan("example.com", proof, recs))
	want := map[string]struct {
		state     string
		conflicts int
		present   bool
	}{
		"mx":        {StateConflict, 1, true},
		"spf":       {StateConflict, 1, false},
		"ownership": {StateConflict, 1, false},
		"dkim1":     {StateConflict, 1, false},
		"dkim2":     {StateConflict, 1, false},
		"dkim3":     {StateMissing, 0, false},
		"dmarc":     {StateConflict, 1, false},
	}
	for k, w := range want {
		it := m[k]
		if it.State != w.state || len(it.Conflicts) != w.conflicts || (it.Present != nil) != w.present {
			t.Errorf("%s: state %s, %d conflicts, present %v; want %+v", k, it.State, len(it.Conflicts), it.Present != nil, w)
		}
	}
	if m["mx"].Conflicts[0].ID != "2" {
		t.Errorf("mx conflict = %+v", m["mx"].Conflicts)
	}
	// The wrong priority makes our own MX a conflict to replace.
	m = byKey(Plan("example.com", proof, []cloudflare.Record{mx("1", "mailserver.purelymail.com", 10)}))
	if it := m["mx"]; it.State != StateConflict || it.Present != nil {
		t.Errorf("wrong priority mx = %+v", it)
	}
}

func TestTXTValue(t *testing.T) {
	for in, want := range map[string]string{
		`v=spf1 -all`:                  "v=spf1 -all",
		`"v=spf1 -all"`:                "v=spf1 -all",
		`"v=DKIM1; p=abc" "def"`:       "v=DKIM1; p=abcdef",
		`"say \"hi\""`:                 `say "hi"`,
		`  "padded"  `:                 "padded",
		`purelymail_ownership_proof=x`: "purelymail_ownership_proof=x",
	} {
		if got := TXTValue(in); got != want {
			t.Errorf("TXTValue(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeDNS struct {
	created []cloudflare.Record
	deleted []string
	failDel string
}

func (f *fakeDNS) Create(_ context.Context, r cloudflare.Record) (cloudflare.Record, error) {
	f.created = append(f.created, r)
	r.ID = "new"
	return r, nil
}

func (f *fakeDNS) Delete(_ context.Context, id string) error {
	if id == f.failDel {
		return errors.New("nope")
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func TestApply(t *testing.T) {
	recs := []cloudflare.Record{
		mx("1", "mailserver.purelymail.com", 50),
		mx("2", "aspmx.l.google.com", 1),
		txt("3", "example.com", `"v=spf1 include:_spf.google.com ~all"`),
		txt("7", "_dmarc.example.com", "v=DMARC1; p=none"),
		cname("5", "purelymail1._domainkey.example.com", "key1.dkimroot.purelymail.com", true),
	}
	items := Plan("example.com", "", recs)
	f := &fakeDNS{failDel: "5"}
	changes := Apply(context.Background(), items, map[string]bool{"mx": true, "spf": true, "dkim1": true}, f)

	// mx: delete the Google MX, keep ours. spf: delete, then create.
	// dkim1: delete fails, so no create. dkim2, dkim3: create.
	// dmarc: conflict not chosen, left alone. ownership: no value, skipped.
	if len(f.deleted) != 2 || f.deleted[0] != "2" || f.deleted[1] != "3" {
		t.Errorf("deleted = %v", f.deleted)
	}
	var names []string
	for _, r := range f.created {
		names = append(names, r.Type+" "+r.Name)
	}
	want := []string{"TXT example.com", "CNAME purelymail2._domainkey.example.com", "CNAME purelymail3._domainkey.example.com"}
	if len(names) != len(want) {
		t.Fatalf("created = %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("created[%d] = %s, want %s", i, names[i], want[i])
		}
	}
	spf := f.created[0]
	if spf.Content != `"`+SPF+`"` || spf.TTL != 1 || spf.Proxied || spf.Comment == "" {
		t.Errorf("spf record = %+v", spf)
	}
	failed := 0
	for _, c := range changes {
		if c.Error != "" {
			failed++
			if c.Key != "dkim1" || c.Action != "delete" {
				t.Errorf("unexpected failure %+v", c)
			}
		}
	}
	if failed != 1 || len(changes) != 6 {
		t.Errorf("changes = %+v", changes)
	}

	// An MX create carries its priority.
	f = &fakeDNS{}
	Apply(context.Background(), Plan("example.com", proof, nil), nil, f)
	if len(f.created) != 7 || f.created[0].Type != "MX" || f.created[0].Priority == nil || *f.created[0].Priority != 50 {
		t.Errorf("empty zone created = %+v", f.created)
	}
}
