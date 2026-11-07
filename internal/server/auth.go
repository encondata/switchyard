package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/encondata/caddyproxymanager/internal/ratelimit"
	"github.com/encondata/caddyproxymanager/internal/store"
)

const (
	sessionCookie = "cpm_session"
	sessionTTL    = 12 * time.Hour
	minPassword   = 8
	maxPassword   = 72 // bcrypt only uses the first 72 bytes
)

type ctxKey int

const userKey ctxKey = 0

func userFrom(r *http.Request) store.User {
	u, _ := r.Context().Value(userKey).(store.User)
	return u
}

// requireUser rejects requests without a valid session. Unless allowPending
// is set, it also rejects users who still have to change their password, so
// the default admin/123456 account can do nothing else until it's changed.
func (s *srv) requireUser(allowPending bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not_signed_in", "Sign in first.")
			return
		}
		u, err := s.store.SessionUser(r.Context(), c.Value)
		if errors.Is(err, store.ErrNotFound) {
			s.clearSessionCookie(w)
			writeError(w, http.StatusUnauthorized, "not_signed_in", "Your session has ended. Sign in again.")
			return
		}
		if err != nil {
			s.internalError(w, err)
			return
		}
		u.MustEnroll2FA = !u.TOTPEnabled && s.require2FA(r)
		if !allowPending {
			if u.MustChangePassword {
				writeError(w, http.StatusForbidden, "password_change_required", "Change your password to continue.")
				return
			}
			if u.MustEnroll2FA {
				writeError(w, http.StatusForbidden, "2fa_enrollment_required", "Set up two-factor sign-in to continue.")
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	}
}

func (s *srv) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ipKey := "ip:" + clientIP(r)
	userKey := userLimitKey(req.Username)
	if !s.attempt(w, ipKey, userKey) {
		return
	}
	u, err := s.store.Authenticate(r.Context(), req.Username, req.Password)
	if errors.Is(err, store.ErrBadCredentials) {
		// The attempt already counted as a failure.
		s.log.Warn("sign-in failed", "username", req.Username, "remote", r.RemoteAddr)
		_ = s.store.AuditEvent(r.Context(), req.Username, "sign_in_failed", "session", 0, map[string]string{"ip": clientIP(r)})
		writeError(w, http.StatusUnauthorized, "bad_credentials", "Wrong username or password.")
		return
	}
	if err != nil {
		s.undo(ipKey, userKey)
		s.internalError(w, err)
		return
	}
	// Right password: this attempt wasn't a failure. The username's count
	// is only cleared once the whole sign-in (including 2FA) succeeds.
	s.undo(ipKey, userKey)
	if u.TOTPEnabled {
		// Password is right; the second factor comes next.
		challenge, err := s.store.CreateChallenge(r.Context(), u.ID)
		if err != nil {
			s.internalError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"totp_required": true, "challenge": challenge})
		return
	}
	s.startSession(w, r, u)
}

// handleLoginTOTP finishes a sign-in with a TOTP or backup code.
func (s *srv) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	ipKey := "ip:" + clientIP(r)
	if !s.attempt(w, ipKey) {
		return
	}
	u, err := s.store.ChallengeUser(r.Context(), req.Challenge)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "challenge_expired", "That sign-in has expired. Enter your password again.")
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	userKey := userLimitKey(u.Username)
	if !s.attempt(w, userKey) {
		s.undo(ipKey)
		return
	}
	if err := s.store.VerifySecondFactor(r.Context(), u.ID, req.Code, s.box); err != nil {
		if errors.Is(err, store.ErrBadCredentials) {
			// Both attempts stay counted as failures.
			s.log.Warn("2FA code rejected", "username", u.Username, "remote", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "bad_code", "That code isn't right. Try the current code from your app, or a backup code.")
			return
		}
		s.internalError(w, err)
		return
	}
	s.undo(ipKey, userKey)
	_ = s.store.DeleteChallenge(r.Context(), req.Challenge)
	s.startSession(w, r, u)
}

func userLimitKey(username string) string {
	return "user:" + strings.ToLower(strings.TrimSpace(username))
}

func (s *srv) limiter(key string) *ratelimit.Failures {
	if strings.HasPrefix(key, "ip:") {
		return s.ipFailures
	}
	return s.userFailures
}

// attempt reserves an attempt on every key (atomically per key), or writes
// a 429 and releases the ones it took.
func (s *srv) attempt(w http.ResponseWriter, keys ...string) bool {
	for i, k := range keys {
		if ok, wait := s.limiter(k).Attempt(k); !ok {
			s.undo(keys[:i]...)
			mins := int(wait.Minutes()) + 1
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				fmt.Sprintf("Too many failed sign-ins. Try again in %d minute(s).", mins))
			return false
		}
	}
	return true
}

func (s *srv) undo(keys ...string) {
	for _, k := range keys {
		s.limiter(k).Undo(k)
	}
}

func (s *srv) startSession(w http.ResponseWriter, r *http.Request, u store.User) {
	token, err := s.store.CreateSession(r.Context(), u.ID, sessionTTL)
	if err != nil {
		s.internalError(w, err)
		return
	}
	//nolint:gosec // Secure is set from CPM_SECURE_COOKIES; off for plain-HTTP LAN access.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	s.userFailures.Reset(userLimitKey(u.Username))
	s.log.Info("signed in", "username", u.Username, "remote", r.RemoteAddr)
	_ = s.store.AuditEvent(r.Context(), u.Username, "sign_in", "session", u.ID, map[string]string{"ip": clientIP(r)})
	u.MustEnroll2FA = s.require2FA(r) && !u.TOTPEnabled
	writeJSON(w, http.StatusOK, u)
}

func (s *srv) require2FA(r *http.Request) bool {
	v, _ := s.store.GetSetting(r.Context(), store.SettingRequire2FA)
	return v == "true"
}

func (s *srv) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteSession(r.Context(), c.Value); err != nil {
			s.internalError(w, err)
			return
		}
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *srv) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userFrom(r))
}

func (s *srv) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	switch {
	case len(req.New) < minPassword:
		writeError(w, http.StatusBadRequest, "weak_password", "The new password must be at least 8 characters.")
		return
	case len(req.New) > maxPassword:
		writeError(w, http.StatusBadRequest, "weak_password", "The new password can be at most 72 characters.")
		return
	case req.New == req.Current || req.New == store.DefaultAdminPassword:
		writeError(w, http.StatusBadRequest, "weak_password", "Choose a password different from the current one.")
		return
	}
	c, _ := r.Cookie(sessionCookie) // present: requireUser checked it
	u := userFrom(r)
	err := s.store.ChangePassword(r.Context(), u.ID, req.Current, req.New, c.Value)
	if errors.Is(err, store.ErrBadCredentials) {
		writeError(w, http.StatusBadRequest, "bad_credentials", "The current password is wrong.")
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	s.log.Info("password changed", "username", u.Username)
	_ = s.store.AuditEvent(r.Context(), u.Username, "change_password", "user", u.ID, nil)
	u.MustChangePassword = false
	writeJSON(w, http.StatusOK, u)
}

func (s *srv) clearSessionCookie(w http.ResponseWriter) {
	//nolint:gosec // Secure is set from CPM_SECURE_COOKIES; off for plain-HTTP LAN access.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secureCookies, SameSite: http.SameSiteStrictMode,
	})
}

// decodeJSON reads a JSON body. Requiring application/json also blocks
// cross-site form posts (browsers can't send that type without CORS).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "Send JSON (Content-Type: application/json).")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body.")
		return false
	}
	return true
}
