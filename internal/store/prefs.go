package store

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Prefs are one user's display preferences.
type Prefs struct {
	// Accent is a #rrggbb color for buttons, links and highlights; empty
	// means the default green.
	Accent string `json:"accent"`
}

var hexColor = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// GetPrefs returns a user's preferences (defaults if never saved).
func (s *Store) GetPrefs(ctx context.Context, userID int64) (Prefs, error) {
	var p Prefs
	err := s.db.QueryRowContext(ctx, `SELECT accent FROM user_prefs WHERE user_id = ?`, userID).Scan(&p.Accent)
	if errors.Is(err, sql.ErrNoRows) {
		return Prefs{}, nil
	}
	return p, err
}

// SetPrefs validates and saves a user's preferences.
func (s *Store) SetPrefs(ctx context.Context, userID int64, p Prefs) (Prefs, error) {
	p.Accent = strings.ToLower(strings.TrimSpace(p.Accent))
	if p.Accent != "" {
		if !hexColor.MatchString(p.Accent) {
			return p, ValidationError{"accent": "Use a color like #0e7c61."}
		}
		// White button text has to stay readable on it (WCAG AA, 4.5:1).
		if contrastWithWhite(p.Accent) < 4.5 {
			return p, ValidationError{"accent": "That color is too light for white text on buttons. Pick a darker shade."}
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_prefs (user_id, accent) VALUES (?, ?)
		ON CONFLICT (user_id) DO UPDATE SET accent = excluded.accent`, userID, p.Accent)
	return p, err
}

// contrastWithWhite is the WCAG contrast ratio of #rrggbb against white.
func contrastWithWhite(hex string) float64 {
	lin := func(i int) float64 {
		v, _ := strconv.ParseUint(hex[i:i+2], 16, 8)
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	l := 0.2126*lin(1) + 0.7152*lin(3) + 0.0722*lin(5)
	return 1.05 / (l + 0.05)
}
