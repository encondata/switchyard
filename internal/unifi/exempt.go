package unifi

import (
	"net/netip"
	"strings"
)

// Exempt removes the exempt addresses and networks (the never-block list)
// from the banned ranges, splitting a range around them where needed. Caddy
// checks never-block before bans, so the firewall must not block what Caddy
// would let through.
func Exempt(bans, exempt []string) []string {
	var ex []netip.Prefix
	for _, e := range exempt {
		if p, ok := prefixOf(e); ok {
			ex = append(ex, p)
		}
	}
	out := []string{}
	for _, b := range bans {
		p, ok := prefixOf(b)
		if !ok {
			continue
		}
		for _, q := range subtract([]netip.Prefix{p}, ex) {
			if q.IsSingleIP() {
				out = append(out, q.Addr().String())
			} else {
				out = append(out, q.String())
			}
		}
	}
	return out
}

func prefixOf(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		a := p.Addr().Unmap()
		return netip.PrefixFrom(a, min(p.Bits(), a.BitLen())).Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// subtract returns the parts of the prefixes not covered by any exempt one.
func subtract(ps, ex []netip.Prefix) []netip.Prefix {
	for _, e := range ex {
		var next []netip.Prefix
		for _, p := range ps {
			next = append(next, cut(p, e)...)
		}
		ps = next
	}
	return ps
}

// cut removes e from p: nothing if e covers p, p itself if they don't
// overlap, else p split in halves around e.
func cut(p, e netip.Prefix) []netip.Prefix {
	if p.Addr().Is4() != e.Addr().Is4() || !p.Overlaps(e) {
		return []netip.Prefix{p}
	}
	if e.Bits() <= p.Bits() {
		return nil // e covers p
	}
	// p is larger: split it and keep cutting the half that holds e.
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	hi := netip.PrefixFrom(lastOf(lo).Next(), p.Bits()+1)
	return append(cut(lo, e), cut(hi, e)...)
}

// lastOf is the last address in p.
func lastOf(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
