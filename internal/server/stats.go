package server

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/encondata/caddyproxymanager/internal/hits"
)

var ranges = map[string]time.Duration{
	"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "45d": 45 * 24 * time.Hour,
}

// statsScope reads ?range=, ?host= (host ID) and ?folder= (folder ID,
// including subfolders). hosts == nil means every host.
func (s *srv) statsScope(r *http.Request) (from, to time.Time, hosts []string, err error) {
	q := r.URL.Query()
	d, ok := ranges[q.Get("range")]
	if !ok {
		d = 24 * time.Hour
	}
	to = time.Now().UTC().Add(time.Minute)
	from = to.Add(-d)
	hostID, _ := strconv.ParseInt(q.Get("host"), 10, 64)
	folderID, _ := strconv.ParseInt(q.Get("folder"), 10, 64)
	if hostID == 0 && folderID == 0 {
		return from, to, nil, nil
	}
	all, err := s.store.ListHosts(r.Context())
	if err != nil {
		return from, to, nil, err
	}
	folders := map[int64]bool{}
	if folderID != 0 {
		st, err := s.store.LoadAccessState(r.Context())
		if err != nil {
			return from, to, nil, err
		}
		folders[folderID] = true
		for grew := true; grew; {
			grew = false
			for _, f := range st.Folders {
				if f.ParentID != nil && folders[*f.ParentID] && !folders[f.ID] {
					folders[f.ID], grew = true, true
				}
			}
		}
	}
	hosts = []string{}
	for _, h := range all {
		if h.ID == hostID || (h.FolderID != nil && folders[*h.FolderID]) {
			hosts = append(hosts, h.Domains...)
		}
	}
	return from, to, hosts, nil
}

func (s *srv) handleStatsOverview(w http.ResponseWriter, r *http.Request) {
	from, to, hosts, err := s.statsScope(r)
	if s.storeError(w, err) {
		return
	}
	o, err := s.hits.Overview(r.Context(), from, to, hosts)
	if s.storeError(w, err) {
		return
	}
	lat, err := s.hits.Latency(r.Context(), from, to, hosts)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"overview": o, "latency": lat})
}

func (s *srv) handleStatsTop(w http.ResponseWriter, r *http.Request) {
	from, to, hosts, err := s.statsScope(r)
	if s.storeError(w, err) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	// Long-range top lists scan many daily rows; cache them for a minute.
	key := r.URL.RawQuery
	if rows, ok := s.topCache.get(key); ok {
		writeJSON(w, http.StatusOK, rows)
		return
	}
	rows, err := s.hits.Top(r.Context(), r.URL.Query().Get("dim"), from, to, hosts, limit)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if to.Sub(from) > 48*time.Hour {
		s.topCache.put(key, rows)
	}
	writeJSON(w, http.StatusOK, rows)
}

// topCache keeps long-range top lists for a minute.
type topCache struct {
	mu      sync.Mutex
	entries map[string]topEntry
}

type topEntry struct {
	rows    []hits.TopRow
	expires time.Time
}

func (c *topCache) get(key string) ([]hits.TopRow, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.rows, true
}

func (c *topCache) put(key string, rows []hits.TopRow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) > 500 {
		c.entries = map[string]topEntry{}
	}
	c.entries[key] = topEntry{rows: rows, expires: time.Now().Add(time.Minute)}
}

// hitView adds a readable reason to a hit.
type hitView struct {
	hits.Hit
	ReasonText string `json:"reason_text,omitempty"`
}

func (s *srv) explain(ctx context.Context, hs []hits.Hit) []hitView {
	names := map[string]string{}
	if ps, err := s.store.ListPolicies(ctx); err == nil {
		for _, p := range ps {
			names["deny:policy:"+strconv.FormatInt(p.ID, 10)] = "Denied by “" + p.Name + "”"
		}
	}
	out := make([]hitView, 0, len(hs))
	for _, h := range hs {
		v := hitView{Hit: h}
		switch {
		case h.Reason == "":
		case h.Reason == "not_allowed":
			v.ReasonText = "Not on an allow list"
		case strings.HasPrefix(h.Reason, "deny:policy:"):
			v.ReasonText = names[h.Reason]
			if v.ReasonText == "" {
				v.ReasonText = "Denied by a deleted policy"
			}
		case h.Reason == "banned":
			v.ReasonText = "Banned"
		case h.Reason == "catchall":
			v.ReasonText = "Honeypot (unknown host)"
		case h.Reason == "trap":
			v.ReasonText = "Honeypot (trap path)"
		default:
			v.ReasonText = h.Reason
		}
		out = append(out, v)
	}
	return out
}

func (s *srv) handleStatsTail(w http.ResponseWriter, r *http.Request) {
	_, _, hosts, err := s.statsScope(r)
	if s.storeError(w, err) {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	hs, err := s.hits.Tail(r.Context(), after, hosts, 100)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, s.explain(r.Context(), hs))
}

func (s *srv) handleStatsIP(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "That isn't an IP address.")
		return
	}
	h, err := s.hits.IP(r.Context(), addr.String(), time.Now().Add(-hits.DefaultRetainHits))
	if s.storeError(w, err) {
		return
	}
	nb, _ := s.store.ListNeverBan(r.Context())
	never := false
	for _, n := range nb {
		if p, err := netip.ParsePrefix(n.CIDR); err == nil && p.Contains(addr) {
			never = true
		} else if a, err := netip.ParseAddr(n.CIDR); err == nil && a == addr {
			never = true
		}
	}
	banned, _ := s.store.IsBanned(r.Context(), addr.String())
	writeJSON(w, http.StatusOK, map[string]any{
		"ip": h.IP, "country": h.Country, "total": h.Total, "blocked": h.Blocked,
		"hosts": h.Hosts, "recent": s.explain(r.Context(), h.Recent), "never_ban": never, "banned": banned,
	})
}
