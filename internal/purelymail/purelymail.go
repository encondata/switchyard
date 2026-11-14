// Package purelymail knows the DNS records Purelymail needs for a custom
// domain, compares them with what a zone has, and makes the changes.
//
// Records are from Purelymail's "Custom Domain Setup" page
// (https://purelymail.com/docs/domainDocs), Cloudflare section.
package purelymail

import (
	"context"
	"regexp"
	"strings"

	"github.com/encondata/switchyard/internal/cloudflare"
)

// The records every Purelymail domain gets. Only the ownership proof
// differs between accounts (it's on Purelymail's Add New Domain page).
const (
	MXHost     = "mailserver.purelymail.com"
	MXPriority = 50
	SPF        = "v=spf1 include:_spf.purelymail.com ~all"
	comment    = "Purelymail (added by Switchyard)"
)

// Want is one record Purelymail needs.
type Want struct {
	Key      string `json:"key"` // mx, spf, ownership, dkim1, dkim2, dkim3, dmarc
	Label    string `json:"label"`
	Type     string `json:"type"`
	Name     string `json:"name"`    // full name, e.g. purelymail1._domainkey.example.com
	Content  string `json:"content"` // TXT values unquoted
	Priority int    `json:"priority,omitempty"`
}

// Records returns Purelymail's records for domain. An empty ownership
// value leaves the ownership record's content empty (see Plan).
func Records(domain, ownership string) []Want {
	d := normName(domain)
	ws := []Want{
		{Key: "mx", Label: "Mail server", Type: "MX", Name: d, Content: MXHost, Priority: MXPriority},
		{Key: "spf", Label: "SPF (who may send)", Type: "TXT", Name: d, Content: SPF},
		{Key: "ownership", Label: "Ownership proof", Type: "TXT", Name: d, Content: ownership},
	}
	for _, n := range []string{"1", "2", "3"} {
		ws = append(ws, Want{
			Key: "dkim" + n, Label: "DKIM key " + n, Type: "CNAME",
			Name: "purelymail" + n + "._domainkey." + d, Content: "key" + n + ".dkimroot.purelymail.com",
		})
	}
	return append(ws, Want{Key: "dmarc", Label: "DMARC", Type: "CNAME", Name: "_dmarc." + d, Content: "dmarcroot.purelymail.com"})
}

// States of a record in a plan.
const (
	StateOK         = "ok"          // there, nothing in the way
	StateMissing    = "missing"     // not there; adding it changes nothing else
	StateConflict   = "conflict"    // other records are in the way (Conflicts)
	StateNeedsValue = "needs_value" // ownership proof not set in Switchyard
)

// Item is one wanted record and how the zone stands for it.
type Item struct {
	Want
	State string `json:"state"`
	// Present is the matching record, when it's already there.
	Present *cloudflare.Record `json:"present,omitempty"`
	// Conflicts are deleted when this record is replaced.
	Conflicts []cloudflare.Record `json:"conflicts"`
	Note      string              `json:"note,omitempty"`
}

// Plan compares what Purelymail needs with a zone's records.
func Plan(domain, ownership string, existing []cloudflare.Record) []Item {
	var out []Item
	for _, w := range Records(domain, ownership) {
		it := Item{Want: w, Conflicts: []cloudflare.Record{}}
		switch w.Type {
		case "MX":
			for _, r := range at(existing, w.Name, "MX") {
				if it.Present == nil && sameHost(r.Content, w.Content) && r.Priority != nil && *r.Priority == w.Priority {
					it.Present = ptr(r)
				} else {
					it.Conflicts = append(it.Conflicts, r)
				}
			}
			it.Note = "Other MX records would send some of your mail elsewhere."
		case "TXT":
			if w.Key == "ownership" && w.Content == "" {
				it.State = StateNeedsValue
				it.Note = "Set your Purelymail ownership proof first."
				out = append(out, it)
				continue
			}
			for _, r := range at(existing, w.Name, "TXT") {
				v := TXTValue(r.Content)
				switch {
				case it.Present == nil && sameText(v, w.Content):
					it.Present = ptr(r)
				case w.Key == "spf" && strings.HasPrefix(strings.ToLower(v), "v=spf1"):
					it.Conflicts = append(it.Conflicts, r)
				case w.Key == "ownership" && sameKind(v, w.Content):
					it.Conflicts = append(it.Conflicts, r)
				}
			}
			if w.Key == "spf" {
				it.Note = "A domain can have only one SPF record. Replacing drops any other senders the old one lists."
			} else {
				it.Note = "An older ownership proof for another account."
			}
		case "CNAME":
			// A CNAME can't share its name with any other record.
			for _, r := range at(existing, w.Name, "") {
				if it.Present == nil && r.Type == "CNAME" && sameHost(r.Content, w.Content) && !r.Proxied {
					it.Present = ptr(r)
				} else {
					it.Conflicts = append(it.Conflicts, r)
				}
			}
			it.Note = "Records at this name are in the way (and it must not be proxied)."
			if w.Key == "dmarc" {
				it.Note = "Purelymail runs your DMARC policy through this record; replacing removes your own."
			}
		}
		switch {
		case len(it.Conflicts) > 0:
			it.State = StateConflict
		case it.Present != nil:
			it.State, it.Note = StateOK, ""
		default:
			it.State, it.Note = StateMissing, ""
		}
		out = append(out, it)
	}
	return out
}

// Status sums a plan up: ok, conflict or incomplete.
func Status(items []Item) string {
	st := StateOK
	for _, it := range items {
		switch it.State {
		case StateConflict:
			return StateConflict
		case StateMissing, StateNeedsValue:
			st = "incomplete"
		}
	}
	return st
}

// DNS makes record changes in one zone.
type DNS interface {
	Create(ctx context.Context, r cloudflare.Record) (cloudflare.Record, error)
	Delete(ctx context.Context, id string) error
}

// Change is one record added or deleted (or the error trying).
type Change struct {
	Key    string            `json:"key"`
	Action string            `json:"action"` // create, delete
	Record cloudflare.Record `json:"record"`
	Error  string            `json:"error,omitempty"`
}

// Apply adds missing records, and replaces conflicting ones whose key is
// in replace (deleting what's in the way first). Other conflicts are left
// alone. It goes on after an error, skipping only that record.
func Apply(ctx context.Context, items []Item, replace map[string]bool, dns DNS) []Change {
	changes := []Change{}
	for _, it := range items {
		switch it.State {
		case StateMissing:
		case StateConflict:
			if !replace[it.Key] {
				continue
			}
		default:
			continue
		}
		failed := false
		for _, r := range it.Conflicts {
			c := Change{Key: it.Key, Action: "delete", Record: r}
			if err := dns.Delete(ctx, r.ID); err != nil {
				c.Error, failed = err.Error(), true
			}
			changes = append(changes, c)
		}
		if failed || it.Present != nil {
			continue
		}
		rec := toRecord(it.Want)
		c := Change{Key: it.Key, Action: "create", Record: rec}
		if got, err := dns.Create(ctx, rec); err != nil {
			c.Error = err.Error()
		} else if got.ID != "" {
			c.Record = got
		}
		changes = append(changes, c)
	}
	return changes
}

func toRecord(w Want) cloudflare.Record {
	r := cloudflare.Record{Type: w.Type, Name: w.Name, Content: w.Content, TTL: 1, Comment: comment}
	switch w.Type {
	case "MX":
		r.Priority = ptr(w.Priority)
	case "TXT":
		r.Content = `"` + strings.ReplaceAll(w.Content, `"`, `\"`) + `"`
	}
	return r
}

// at returns the records named name (of type typ, or any type if "").
func at(rs []cloudflare.Record, name, typ string) []cloudflare.Record {
	var out []cloudflare.Record
	for _, r := range rs {
		if normName(r.Name) == name && (typ == "" || strings.EqualFold(r.Type, typ)) {
			out = append(out, r)
		}
	}
	return out
}

var quoted = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// TXTValue is a TXT record's text: Cloudflare may give it quoted, and
// long values as several quoted strings.
func TXTValue(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, `"`) {
		return s
	}
	var b strings.Builder
	for _, m := range quoted.FindAllStringSubmatch(s, -1) {
		b.WriteString(strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(m[1]))
	}
	return b.String()
}

// sameKind reports whether two values are both key=… for the same key
// (an ownership proof from another Purelymail account).
func sameKind(a, b string) bool {
	ka, _, okA := strings.Cut(a, "=")
	kb, _, okB := strings.Cut(b, "=")
	return okA && okB && ka != "" && strings.EqualFold(ka, kb)
}

func sameText(a, b string) bool {
	return strings.Join(strings.Fields(a), " ") == strings.Join(strings.Fields(b), " ")
}

func sameHost(a, b string) bool { return normName(a) == normName(b) }

func normName(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

func ptr[T any](v T) *T { return &v }
