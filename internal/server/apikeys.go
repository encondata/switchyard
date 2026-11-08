package server

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/encondata/switchyard/internal/store"
)

// apiKeyFrom returns an API key sent as "Authorization: Bearer sy_..." or
// "X-API-Key: sy_...".
func apiKeyFrom(r *http.Request) (string, bool) {
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" {
		return k, true
	}
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:]), true
	}
	return "", false
}

// keyAuth runs h for a request made with an API key, if the key is valid
// and has been given this operation. The handler sees a stand-in user named
// "api:<key name>" with exactly the role the operation needs, so audit
// entries name the key and admin-only extras (like a host's advanced JSON)
// stay off unless the operation itself is an admin one.
func (s *srv) keyAuth(op Op, token string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !op.Keyable {
			writeError(w, http.StatusForbidden, "not_for_api_keys", "API keys can't be used for this; sign in instead.")
			return
		}
		k, err := s.store.APIKeyByToken(r.Context(), token)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid_api_key", "That API key isn't valid, or it has been revoked or has expired.")
			return
		}
		if err != nil {
			s.internalError(w, err)
			return
		}
		if !k.Allows(op.ID) {
			writeError(w, http.StatusForbidden, "missing_permission",
				"This API key doesn't have permission for "+op.ID+". An admin can add it on the API keys page.")
			return
		}
		if err := s.store.TouchAPIKey(r.Context(), k.ID, clientIP(r)); err != nil {
			s.log.Warn("recording API key use", "err", err)
		}
		role := op.Role
		if role == rolePending {
			role = roleViewer
		}
		u := store.User{Username: "api:" + k.Name, Role: role}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	}
}

func (s *srv) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAPIKeys(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

// keyRequest is what admins send to make or change a key.
func (s *srv) keyRequest(w http.ResponseWriter, r *http.Request) (name string, perms []string, expires *time.Time, ok bool) {
	var req apiKeyBody
	if !decodeJSON(w, r, &req) {
		return "", nil, nil, false
	}
	keyable := map[string]bool{}
	for _, rt := range s.routes() {
		if rt.Keyable {
			keyable[rt.ID] = true
		}
	}
	var bad []string
	for _, p := range req.Permissions {
		if !keyable[p] {
			bad = append(bad, p)
		}
	}
	if len(bad) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid", "message": "Fix the highlighted fields.",
			"fields": map[string]string{"permissions": "Not operations a key can have: " + strings.Join(bad, ", ")}})
		return "", nil, nil, false
	}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			if t, err = time.Parse("2006-01-02", *req.ExpiresAt); err == nil {
				t = t.Add(24*time.Hour - time.Second) // the end of that day
			}
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid", "message": "Fix the highlighted fields.",
				"fields": map[string]string{"expires_at": "Use a date like 2027-01-31."}})
			return "", nil, nil, false
		}
		expires = &t
	}
	return req.Name, req.Permissions, expires, true
}

func (s *srv) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	name, perms, expires, ok := s.keyRequest(w, r)
	if !ok {
		return
	}
	k, token, err := s.store.CreateAPIKey(r.Context(), name, perms, expires, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	s.log.Info("API key created", "name", k.Name, "by", userFrom(r).Username, "permissions", len(k.Permissions))
	writeJSON(w, http.StatusCreated, map[string]any{"key": k, "token": token})
}

func (s *srv) handleUpdateAPIKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	name, perms, expires, ok := s.keyRequest(w, r)
	if !ok {
		return
	}
	k, err := s.store.UpdateAPIKey(r.Context(), id, name, perms, expires, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, k)
}

func (s *srv) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.RevokeAPIKey(r.Context(), id, userFrom(r).Username)) {
		return
	}
	s.log.Info("API key revoked", "id", id, "by", userFrom(r).Username)
	w.WriteHeader(http.StatusNoContent)
}

// handleKeyOperations lists what a key can be given, grouped by area, for
// the permission picker.
func (s *srv) handleKeyOperations(w http.ResponseWriter, _ *http.Request) {
	ops := []Op{}
	for _, rt := range s.routes() {
		if rt.Keyable && s.has(rt.needs) {
			ops = append(ops, rt.Op)
		}
	}
	sort.SliceStable(ops, func(i, j int) bool { return areaOrder(ops[i].Area) < areaOrder(ops[j].Area) })
	writeJSON(w, http.StatusOK, ops)
}

var areas = []string{"Hosts", "Folders", "Access", "DNS", "Certificates", "Config", "Traffic", "Honeypot", "Firewall", "Health", "Users", "Import", "API keys", "Account"}

func areaOrder(a string) int {
	for i, x := range areas {
		if x == a {
			return i
		}
	}
	return len(areas)
}
