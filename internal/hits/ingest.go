package hits

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/encondata/switchyard/internal/geoip"
)

// Ingester tails Caddy's JSON access log and stores hits (CPM-22).
type Ingester struct {
	DB   *DB
	File string // Caddy's access log, as CPM sees it
	Geo  *geoip.DB
	Log  *slog.Logger
	// Interval between reads (2s by default, so the dashboard is current
	// within seconds).
	Interval      time.Duration
	RetainHits    time.Duration
	RetainRollups time.Duration
	// OnHits, if set, sees every stored batch (the honeypot scores it).
	OnHits func(ctx context.Context, batch []Hit)

	f      *os.File
	ident  string
	offset int64
	rd     *bufio.Reader
}

// accessEntry is the part of a Caddy access log line CPM uses.
type accessEntry struct {
	TS      float64 `json:"ts"`
	Request struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
	Duration  float64 `json:"duration"`
	Size      int64   `json:"size"`
	Status    int     `json:"status"`
	UserAgent string  `json:"user_agent"`
	Blocked   string  `json:"cpm_blocked"`
	Honeypot  string  `json:"cpm_honeypot"`
}

// ParseLine turns one access log line into a Hit.
func ParseLine(line []byte, geo *geoip.DB) (Hit, bool) {
	var e accessEntry
	if json.Unmarshal(line, &e) != nil || e.Request.Method == "" {
		return Hit{}, false
	}
	sec, frac := math.Modf(e.TS)
	h := Hit{
		TS:         time.Unix(int64(sec), int64(frac*1e9)).UTC(),
		Method:     e.Request.Method,
		Status:     e.Status,
		Bytes:      e.Size,
		DurationMS: e.Duration * 1000,
		Matched:    "allowed",
	}
	h.ClientIP = e.Request.ClientIP
	if h.ClientIP == "" {
		h.ClientIP = e.Request.RemoteIP
	}
	h.Host = strings.ToLower(e.Request.Host)
	if host, _, err := net.SplitHostPort(h.Host); err == nil {
		h.Host = host
	}
	h.Path = e.Request.URI
	if i := strings.IndexByte(h.Path, '?'); i >= 0 {
		h.Path = h.Path[:i] // query strings can hold tokens; don't keep them
	}
	h.UserAgent = e.UserAgent
	if ua := e.Request.Headers["User-Agent"]; h.UserAgent == "" && len(ua) > 0 {
		h.UserAgent = ua[0] // logs from before the header filter
	}
	if len(h.UserAgent) > 300 {
		h.UserAgent = h.UserAgent[:300]
	}
	switch {
	case e.Honeypot != "":
		h.Matched, h.Reason = "honeypot", e.Honeypot
	case e.Blocked != "":
		h.Matched, h.Reason = "blocked", e.Blocked
	}
	h.Country = geo.Country(h.ClientIP)
	return h, true
}

func fileIdent(info os.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	return info.ModTime().String()
}

// Run reads the log until ctx ends, and prunes old data every hour.
func (in *Ingester) Run(ctx context.Context) {
	interval := in.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	lastPrune := time.Time{}
	for {
		if err := in.Poll(ctx); err != nil && ctx.Err() == nil {
			in.Log.Warn("access log ingest", "err", err)
		}
		if time.Since(lastPrune) > time.Hour {
			lastPrune = time.Now()
			if n, err := in.DB.Prune(ctx, time.Now(), in.retainHits(), in.retainRollups()); err != nil && ctx.Err() == nil {
				in.Log.Warn("pruning hits", "err", err)
			} else if n > 0 {
				in.Log.Info("pruned old hits", "deleted", n)
			}
		}
		select {
		case <-ctx.Done():
			if in.f != nil {
				_ = in.f.Close()
			}
			return
		case <-t.C:
		}
	}
}

func (in *Ingester) retainHits() time.Duration {
	if in.RetainHits > 0 {
		return in.RetainHits
	}
	return DefaultRetainHits
}

func (in *Ingester) retainRollups() time.Duration {
	if in.RetainRollups > 0 {
		return in.RetainRollups
	}
	return DefaultRetainRollups
}

// Poll reads everything new in the log. When Caddy rotates the file, the
// rest of the old file is read before moving to the new one.
func (in *Ingester) Poll(ctx context.Context) error {
	if in.f == nil {
		if err := in.open(ctx); err != nil {
			return err
		}
		if in.f == nil {
			return nil // no log yet
		}
	}
	if err := in.drain(ctx); err != nil {
		return err
	}
	info, err := os.Stat(in.File)
	if err != nil {
		return nil //nolint:nilerr // file briefly missing during rotation
	}
	if id := fileIdent(info); id != in.ident || info.Size() < in.offset {
		// Rotated (or truncated): the old file is fully read; switch.
		_ = in.f.Close()
		in.f = nil
		in.ident, in.offset = "", 0
		if err := in.open(ctx); err != nil {
			return err
		}
		if in.f != nil {
			return in.drain(ctx)
		}
	}
	return nil
}

func (in *Ingester) open(ctx context.Context) error {
	f, err := os.Open(in.File)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	id := fileIdent(info)
	savedID, savedOff, err := in.DB.Offset(ctx, in.File)
	if err != nil {
		_ = f.Close()
		return err
	}
	in.offset = 0
	if savedID == id && savedOff <= info.Size() {
		in.offset = savedOff
	}
	if _, err := f.Seek(in.offset, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}
	in.f, in.ident, in.rd = f, id, bufio.NewReaderSize(f, 256<<10)
	return nil
}

func (in *Ingester) drain(ctx context.Context) error {
	var batch []Hit
	flush := func() error {
		if err := in.DB.Insert(ctx, batch); err != nil {
			return err
		}
		if in.OnHits != nil && len(batch) > 0 {
			in.OnHits(ctx, batch)
		}
		batch = batch[:0]
		return in.DB.SaveOffset(ctx, in.File, in.ident, in.offset)
	}
	for {
		line, err := in.rd.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			in.offset += int64(len(line))
			if h, ok := ParseLine(line, in.Geo); ok {
				batch = append(batch, h)
			}
			if len(batch) >= 1000 {
				if err := flush(); err != nil {
					return err
				}
			}
			continue
		}
		// Partial line (Caddy is mid-write): rewind and read it next time.
		if len(line) > 0 {
			if _, serr := in.f.Seek(in.offset, io.SeekStart); serr != nil {
				return serr
			}
			in.rd.Reset(in.f)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return flush()
	}
}
