package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/encondata/switchyard/internal/store"
	"github.com/encondata/switchyard/internal/totp"
)

// --- the signed-in user's own two-factor settings ---

func (s *srv) handle2FAStatus(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	left, err := s.store.BackupCodesLeft(r.Context(), u.ID)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":           u.TOTPEnabled,
		"required":          s.require2FA(r),
		"backup_codes_left": left,
		"available":         s.box.Ready(),
	})
}

func (s *srv) handle2FABegin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	secret, err := s.store.BeginTOTP(r.Context(), u.ID, s.box)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret": secret,
		"uri":    totp.URI("CaddyProxyManager", u.Username, secret),
	})
}

func (s *srv) handle2FAConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u := userFrom(r)
	codes, err := s.store.ConfirmTOTP(r.Context(), u.ID, req.Code, s.box, u.Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": codes})
}

func (s *srv) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u := userFrom(r)
	if s.require2FA(r) {
		writeError(w, http.StatusConflict, "conflict", "Two-factor sign-in is required for everyone, so it can't be turned off.")
		return
	}
	if _, err := s.store.Authenticate(r.Context(), u.Username, req.Password); err != nil {
		if errors.Is(err, store.ErrBadCredentials) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid", "message": "Wrong password.", "fields": map[string]string{"password": "wrong password"}})
			return
		}
		s.internalError(w, err)
		return
	}
	if s.storeError(w, s.store.DisableTOTP(r.Context(), u.ID, u.Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- user management (admins) ---

func (s *srv) handleListUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.store.ListUsers(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, us)
}

func (s *srv) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.store.CreateUser(r.Context(), req.Username, req.Role, req.Password, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *srv) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Role     string `json:"role"`
		Disabled bool   `json:"disabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	me := userFrom(r)
	if id == me.ID && (req.Disabled || req.Role != me.Role) {
		writeError(w, http.StatusConflict, "conflict", "You can't change your own role or disable yourself.")
		return
	}
	u, err := s.store.UpdateUser(r.Context(), id, req.Role, req.Disabled, me.Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *srv) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.storeError(w, s.store.ResetPassword(r.Context(), id, req.Password, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *srv) handleResetUser2FA(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.DisableTOTP(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *srv) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if id == userFrom(r).ID {
		writeError(w, http.StatusConflict, "conflict", "You can't delete yourself.")
		return
	}
	if s.storeError(w, s.store.DeleteUser(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *srv) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"require_2fa": s.require2FA(r), "secrets_ready": s.box.Ready()})
}

func (s *srv) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Require2FA bool `json:"require_2fa"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	me := userFrom(r)
	if req.Require2FA && !me.TOTPEnabled {
		writeError(w, http.StatusConflict, "conflict", "Turn on two-factor sign-in for your own account first, so you don't lock yourself out.")
		return
	}
	if req.Require2FA && !s.box.Ready() {
		writeError(w, http.StatusConflict, "conflict", "Two-factor sign-in needs CPM_SECRET_KEY to be set.")
		return
	}
	if s.storeError(w, s.store.SetSetting(r.Context(), store.SettingRequire2FA, strconv.FormatBool(req.Require2FA), me.Username)) {
		return
	}
	s.handleGetSettings(w, r)
}

func (s *srv) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	entries, err := s.store.ListAudit(r.Context(), before, q.Get("entity"), q.Get("user"), limit)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
