package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Zone is a Cloudflare zone (a domain whose DNS Cloudflare serves).
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Record is one DNS record in a zone. Name is the full name
// (mail.example.com, or example.com for the apex).
type Record struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Priority *int   `json:"priority,omitempty"` // MX only
	TTL      int    `json:"ttl,omitempty"`      // 1 = automatic
	Proxied  bool   `json:"proxied"`
	Comment  string `json:"comment,omitempty"`
}

// ErrNoZone means the token can't see a zone for the domain.
var ErrNoZone = errors.New("no Cloudflare zone for this domain")

func do(ctx context.Context, token, method, path string, body any) (envelope, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return envelope{}, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, BaseURL+path, rd)
	if err != nil {
		return envelope{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return send(req, token)
}

// FindZone returns the zone that holds domain: the domain itself, or the
// closest parent the token can see (for mail on a subdomain).
func FindZone(ctx context.Context, token, domain string) (Zone, error) {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		env, err := get(ctx, token, "/zones?name="+url.QueryEscape(name))
		if err != nil {
			return Zone{}, err
		}
		var zs []Zone
		_ = json.Unmarshal(env.Result, &zs)
		for _, z := range zs {
			if strings.EqualFold(z.Name, name) {
				return z, nil
			}
		}
	}
	return Zone{}, ErrNoZone
}

// ListRecords returns every record in a zone.
func ListRecords(ctx context.Context, token, zoneID string) ([]Record, error) {
	var out []Record
	for page := 1; ; page++ {
		env, err := get(ctx, token, fmt.Sprintf("/zones/%s/dns_records?per_page=500&page=%d", url.PathEscape(zoneID), page))
		if err != nil {
			return nil, err
		}
		var rs []Record
		if err := json.Unmarshal(env.Result, &rs); err != nil {
			return nil, fmt.Errorf("unexpected record list from Cloudflare: %w", err)
		}
		out = append(out, rs...)
		if env.ResultInfo.TotalPages <= page || len(rs) == 0 {
			return out, nil
		}
	}
}

// CreateRecord adds a record and returns it as Cloudflare stored it.
func CreateRecord(ctx context.Context, token, zoneID string, r Record) (Record, error) {
	r.ID = ""
	env, err := do(ctx, token, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", r)
	if err != nil {
		return Record{}, err
	}
	var got Record
	_ = json.Unmarshal(env.Result, &got)
	return got, nil
}

// DeleteRecord removes a record.
func DeleteRecord(ctx context.Context, token, zoneID, recordID string) error {
	_, err := do(ctx, token, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil)
	return err
}
