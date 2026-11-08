package unifi

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/encondata/switchyard/internal/secrets"
	"github.com/encondata/switchyard/internal/store"
)

// Placeholders for an empty list (the API needs at least one item):
// documentation addresses (RFC 5737 / RFC 3849) that never appear on the
// internet, so blocking them blocks nothing.
const (
	placeholderV4 = "192.0.2.255"
	placeholderV6 = "2001:db8::ffff"
)

// Status is what the last sync did, for the settings page.
type Status struct {
	Enabled   bool       `json:"enabled"`
	LastSync  *time.Time `json:"last_sync"`
	LastError string     `json:"last_error"`
	IPv4      int        `json:"ipv4"` // addresses/networks sent
	IPv6      int        `json:"ipv6"`
	Lists     []ListInfo `json:"lists"`
}

// ListInfo is one list on the console and the policies that use it.
type ListInfo struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Type     string       `json:"type"`
	Policies []PolicyInfo `json:"policies"`
}

// PolicyInfo is a firewall policy that uses a list.
type PolicyInfo struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Action  string `json:"action"`
}

// Syncer keeps the console's lists equal to the ban list.
type Syncer struct {
	Store *store.Store
	Box   *secrets.Box
	Log   *slog.Logger
	// Every is the backstop interval (default 5 minutes).
	Every time.Duration

	wake     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	status   Status
	lastSent string
	lastFull time.Time
}

func (s *Syncer) init() {
	s.once.Do(func() { s.wake = make(chan struct{}, 1) })
}

// Trigger asks for a sync soon (bans changed). It never blocks.
func (s *Syncer) Trigger() {
	s.init()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Status returns what the last sync did.
func (s *Syncer) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	st.Lists = append([]ListInfo(nil), st.Lists...)
	return st
}

// Run syncs on Trigger (a few seconds later, so a burst of bans is one
// sync) and every Every as a backstop, until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	s.init()
	every := s.Every
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	s.syncLogged(ctx, false)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncLogged(ctx, false)
		case <-s.wake:
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			s.syncLogged(ctx, false)
		}
	}
}

func (s *Syncer) syncLogged(ctx context.Context, force bool) {
	if err := s.Sync(ctx, force); err != nil && ctx.Err() == nil {
		s.Log.Warn("unifi: sync failed", "err", err)
	}
}

// Sync sends the ban list to the console now. Unless force is set, it skips
// sending lists that haven't changed (but still checks them every 30
// minutes, in case someone edited them on the console).
func (s *Syncer) Sync(ctx context.Context, force bool) error {
	settings, err := s.Store.UniFi(ctx)
	if err != nil {
		return err
	}
	if !settings.Enabled {
		s.mu.Lock()
		s.status = Status{}
		s.lastSent = ""
		s.mu.Unlock()
		return nil
	}
	err = s.sync(ctx, settings, force)
	now := time.Now().UTC()
	s.mu.Lock()
	s.status.Enabled = true
	s.status.LastSync = &now
	s.status.LastError = ""
	if err != nil {
		s.status.LastError = err.Error()
		s.lastSent = ""
	}
	s.mu.Unlock()
	return err
}

func (s *Syncer) sync(ctx context.Context, settings store.UniFiSettings, force bool) error {
	key, err := s.Store.UniFiKey(ctx, s.Box)
	if err != nil {
		return err
	}
	if key == "" {
		return errors.New("no API key saved")
	}
	c := &Client{BaseURL: settings.URL, APIKey: key, CertSHA256: settings.CertSHA256}
	bans, err := s.Store.ActiveBanRanges(ctx)
	if err != nil {
		return err
	}
	// Never-block wins in Caddy, so it must win at the firewall too.
	never, err := s.Store.ListNeverBan(ctx)
	if err != nil {
		return err
	}
	exempt := make([]string, 0, len(never))
	for _, n := range never {
		exempt = append(exempt, n.CIDR)
	}
	v4, v6 := Items(Exempt(bans, exempt))
	sent := settings.URL + "|" + settings.SiteID + "|" + settings.ListName + "|" + join(v4) + "|" + join(v6)
	s.mu.Lock()
	unchanged := sent == s.lastSent && time.Since(s.lastFull) < 30*time.Minute
	s.mu.Unlock()
	if unchanged && !force {
		return nil
	}

	state, err := s.Store.UniFiState(ctx)
	if err != nil {
		return err
	}
	lists, err := c.Lists(ctx, settings.SiteID)
	if err != nil {
		return err
	}
	byID := map[string]List{}
	for _, l := range lists {
		byID[l.ID] = l
	}
	ensure := func(id *string, typ, name string, items []Item) error {
		// The remembered list, or one with our name, or a new one.
		if _, ok := byID[*id]; !ok {
			*id = ""
			for _, l := range lists {
				if l.Name == name && l.Type == typ {
					*id = l.ID
					break
				}
			}
		}
		l := List{Name: name, Type: typ, Items: items}
		if *id != "" {
			return c.UpdateList(ctx, settings.SiteID, *id, l)
		}
		created, err := c.CreateList(ctx, settings.SiteID, l)
		if err != nil {
			return err
		}
		*id = created.ID
		return nil
	}
	if err := ensure(&state.IPv4ListID, "IPV4_ADDRESSES", settings.ListName+" (IPv4)", orPlaceholder(v4, placeholderV4)); err != nil {
		return err
	}
	// The IPv6 list is only made once there's an IPv6 ban, then kept.
	if len(v6) > 0 || state.IPv6ListID != "" {
		if err := ensure(&state.IPv6ListID, "IPV6_ADDRESSES", settings.ListName+" (IPv6)", orPlaceholder(v6, placeholderV6)); err != nil {
			return err
		}
	}
	if err := s.Store.SaveUniFiState(ctx, state); err != nil {
		return err
	}

	// Which firewall policies use the lists (so the page can say whether
	// anything actually blocks them).
	infos := []ListInfo{{ID: state.IPv4ListID, Name: settings.ListName + " (IPv4)", Type: "IPv4", Policies: []PolicyInfo{}}}
	if state.IPv6ListID != "" {
		infos = append(infos, ListInfo{ID: state.IPv6ListID, Name: settings.ListName + " (IPv6)", Type: "IPv6", Policies: []PolicyInfo{}})
	}
	policies, perr := c.Policies(ctx, settings.SiteID)
	for i := range infos {
		for _, p := range policies {
			if p.Uses(infos[i].ID) {
				infos[i].Policies = append(infos[i].Policies, PolicyInfo{Name: p.Name, Enabled: p.Enabled, Action: p.Action.Type})
			}
		}
	}
	s.mu.Lock()
	s.status.IPv4, s.status.IPv6 = len(v4), len(v6)
	s.status.Lists = infos
	s.lastSent = sent
	s.lastFull = time.Now()
	s.mu.Unlock()
	if perr != nil {
		return errors.New("lists updated, but reading firewall policies failed: " + perr.Error())
	}
	return nil
}

// Items turns ban ranges into IPv4 and IPv6 list items: single addresses as
// IP_ADDRESS, networks as SUBNET. Unreadable entries are skipped.
func Items(bans []string) (v4, v6 []Item) {
	seen := map[string]bool{}
	for _, b := range bans {
		var p netip.Prefix
		if strings.Contains(b, "/") {
			pp, err := netip.ParsePrefix(b)
			if err != nil {
				continue
			}
			p = pp.Masked()
		} else {
			a, err := netip.ParseAddr(b)
			if err != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		addr := p.Addr().Unmap()
		p = netip.PrefixFrom(addr, min(p.Bits(), addr.BitLen()))
		it := Item{Type: "SUBNET", Value: p.String()}
		if p.IsSingleIP() {
			it = Item{Type: "IP_ADDRESS", Value: addr.String()}
		}
		if seen[it.Value] {
			continue
		}
		seen[it.Value] = true
		if addr.Is4() {
			v4 = append(v4, it)
		} else {
			v6 = append(v6, it)
		}
	}
	sortItems(v4)
	sortItems(v6)
	return v4, v6
}

func sortItems(it []Item) {
	sort.Slice(it, func(i, j int) bool { return it[i].Value < it[j].Value })
}

func orPlaceholder(items []Item, placeholder string) []Item {
	if len(items) > 0 {
		return items
	}
	return []Item{{Type: "IP_ADDRESS", Value: placeholder}}
}

func join(items []Item) string {
	var b strings.Builder
	for _, it := range items {
		b.WriteString(it.Value)
		b.WriteByte(',')
	}
	return b.String()
}
