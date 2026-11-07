package server

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"time"

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
		if u.MustChangePassword && !allowPending {
			writeError(w, http.StatusForbidden, "password_change_required", "Change your password to continue.")
			return
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
	u, err := s.store.Authenticate(r.Context(), req.Username, req.Password)
	if errors.Is(err, store.ErrBadCredentials) {
		s.log.Warn("sign-in failed", "username", req.Username, "remote", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "bad_credentials", "Wrong username or password.")
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
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
	s.log.Info("signed in", "username", u.Username, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, u)
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
