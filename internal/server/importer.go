package server

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/encondata/switchyard/internal/npmimport"
)

// pendingImports holds previewed plans until they're run (10 minutes).
type pendingImports struct {
	mu    sync.Mutex
	plans map[string]pendingPlan
}

type pendingPlan struct {
	plan    npmimport.Plan
	expires time.Time
	user    string
}

func (p *pendingImports) put(user string, plan npmimport.Plan) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.plans == nil {
		p.plans = map[string]pendingPlan{}
	}
	for k, v := range p.plans {
		if time.Now().After(v.expires) {
			delete(p.plans, k)
		}
	}
	p.plans[id] = pendingPlan{plan: plan, expires: time.Now().Add(10 * time.Minute), user: user}
	return id, nil
}

func (p *pendingImports) take(id, user string) (npmimport.Plan, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.plans[id]
	if !ok || e.user != user || time.Now().After(e.expires) {
		return npmimport.Plan{}, false
	}
	delete(p.plans, id)
	return e.plan, true
}

// handleImportPreview reads NPM's records and shows what an import would
// do. Send JSON {"api": {url, email, password}} to read a running NPM
// through its API, JSON {"mysql": {...}} for a MySQL database, or the NPM
// database.sqlite file as the body (Content-Type: application/vnd.sqlite3).
func (s *srv) handleImportPreview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var src npmimport.Source
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mt {
	case "application/vnd.sqlite3", "application/octet-stream":
		tmp, err := os.CreateTemp(s.dataDir, ".npm-import-*.sqlite")
		if err != nil {
			s.internalError(w, err)
			return
		}
		defer func() { _ = os.Remove(tmp.Name()) }()
		_, err = io.Copy(tmp, http.MaxBytesReader(w, r.Body, maxBackup))
		_ = tmp.Close()
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "Upload failed or the file is too large.")
			return
		}
		db, err := npmimport.OpenSQLite(tmp.Name())
		if err != nil {
			s.internalError(w, err)
			return
		}
		defer func() { _ = db.Close() }()
		src = npmimport.FromDB(db)
	case "application/json":
		var req struct {
			API   *npmimport.APIConfig   `json:"api"`
			MySQL *npmimport.MySQLConfig `json:"mysql"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "Invalid JSON body.")
			return
		}
		switch {
		case req.API != nil:
			var err error
			if src, err = npmimport.FetchAPI(ctx, *req.API); err != nil {
				writeError(w, http.StatusBadRequest, "import_failed", sentence(err.Error()))
				return
			}
		case req.MySQL != nil:
			db, err := npmimport.OpenMySQL(*req.MySQL)
			if err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", err.Error())
				return
			}
			defer func() { _ = db.Close() }()
			src = npmimport.FromDB(db)
		default:
			writeError(w, http.StatusBadRequest, "bad_request", "Send NPM's address and admin login, or MySQL connection details.")
			return
		}
	default:
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "Connect to NPM, upload its database.sqlite, or send MySQL connection details.")
		return
	}

	opts := npmimport.Options{ExistingDomains: map[string]bool{}}
	hosts, err := s.store.ListHosts(ctx)
	if s.storeError(w, err) {
		return
	}
	for _, h := range hosts {
		for _, d := range h.Domains {
			opts.ExistingDomains[strings.ToLower(d)] = true
		}
	}
	if providers, err := s.store.ListDNSProviders(ctx); err == nil && len(providers) > 0 {
		opts.DNSProviderID = providers[0].ID
	}
	plan, err := npmimport.Build(ctx, src, opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, "import_failed", err.Error())
		return
	}
	id, err := s.imports.put(userFrom(r).Username, plan)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan_id": id, "plan": plan})
}

func (s *srv) handleImportRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	u := userFrom(r)
	plan, ok := s.imports.take(req.PlanID, u.Username)
	if !ok {
		writeError(w, http.StatusConflict, "conflict", "That preview has expired. Preview the import again.")
		return
	}
	res, err := npmimport.Apply(r.Context(), s.store, plan, u.Username)
	if s.storeError(w, err) {
		return
	}
	s.log.Info("NPM import", "username", u.Username, "hosts", res.HostsCreated, "policies", res.PoliciesCreated)
	writeJSON(w, http.StatusOK, res)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 32)
	for i, v := range b {
		out[i*2], out[i*2+1] = hex[v>>4], hex[v&15]
	}
	return string(out), nil
}

// sentence capitalizes an error message for display.
func sentence(msg string) string {
	if msg == "" {
		return msg
	}
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}
