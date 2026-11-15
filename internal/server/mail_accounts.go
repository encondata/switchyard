package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/encondata/switchyard/internal/purelymail"
	"github.com/encondata/switchyard/internal/store"
)

// Email accounts on mail domains: Purelymail users whose passwords
// Switchyard keeps (sealed), so they can be shown again. Each domain has a
// shared password its accounts use unless they have their own.

type (
	mailAccountView struct {
		store.MailAccount
		// OnPurelymail is whether Purelymail has the account (absent when
		// Purelymail couldn't be asked).
		OnPurelymail *bool `json:"on_purelymail,omitempty"`
	}
	mailAccountsView struct {
		Domain   store.MailDomain  `json:"domain"`
		Accounts []mailAccountView `json:"accounts"`
		// Others are addresses on the domain at Purelymail that Switchyard
		// doesn't manage (made by hand there).
		Others   []string `json:"others"`
		Defaults []string `json:"defaults"`
		KeySet   bool     `json:"key_set"`
		Error    string   `json:"error,omitempty"`
	}
	mailAccountsBody struct {
		Names []string `json:"names"`
		// Password is the accounts' own password; "" uses the domain's
		// shared one.
		Password string `json:"password,omitempty"`
		// TakeOver manages accounts that already exist at Purelymail,
		// setting their password.
		TakeOver bool `json:"take_over,omitempty"`
	}
	mailAccountResult struct {
		Name    string `json:"name"`
		Address string `json:"address,omitempty"`
		Error   string `json:"error,omitempty"`
		Exists  bool   `json:"exists,omitempty"` // at Purelymail already (take_over manages it)
	}
	mailAccountsResult struct {
		mailAccountsView
		Results []mailAccountResult `json:"results"`
	}
	mailPasswordBody struct {
		Password string `json:"password"`
		// UseDomain (accounts only) puts the account back on the shared
		// password.
		UseDomain bool `json:"use_domain,omitempty"`
	}
	mailPasswordFailure struct {
		Address string `json:"address"`
		Error   string `json:"error"`
	}
	mailPasswordResult struct {
		mailAccountsView
		// Failed are accounts Purelymail didn't change: they keep the old
		// password, now as their own.
		Failed []mailPasswordFailure `json:"failed"`
	}
	revealedPassword struct {
		Password string `json:"password"`
	}
)

// pathMailDomain loads the mail domain in the path.
func (s *srv) pathMailDomain(w http.ResponseWriter, r *http.Request) (store.MailDomain, bool) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return store.MailDomain{}, false
	}
	m, err := s.store.GetMailDomain(r.Context(), id)
	return m, !s.storeError(w, err)
}

// needPurelymail is the Purelymail client, or a 409 when no key is stored.
func (s *srv) needPurelymail(w http.ResponseWriter, r *http.Request) (purelymail.Client, bool) {
	pm, ok := s.purelymailClient(r.Context())
	if !ok {
		writeError(w, http.StatusConflict, "conflict", "Save a Purelymail API key first.")
	}
	return pm, ok
}

func hasUser(users []string, address string) bool {
	return slices.ContainsFunc(users, func(u string) bool { return strings.EqualFold(u, address) })
}

// accountsView lists a domain's accounts and, with an API key, checks them
// against Purelymail.
func (s *srv) accountsView(ctx context.Context, id int64) (mailAccountsView, error) {
	m, err := s.store.GetMailDomain(ctx, id)
	if err != nil {
		return mailAccountsView{}, err
	}
	accounts, err := s.store.ListMailAccounts(ctx, id)
	if err != nil {
		return mailAccountsView{}, err
	}
	v := mailAccountsView{Domain: m, Accounts: make([]mailAccountView, len(accounts)), Others: []string{}, Defaults: store.DefaultMailAccounts}
	for i, a := range accounts {
		v.Accounts[i] = mailAccountView{MailAccount: a}
	}
	pm, ok := s.purelymailClient(ctx)
	if !ok {
		return v, nil
	}
	v.KeySet = true
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	users, err := pm.ListUsers(cctx)
	if err != nil {
		v.Error = err.Error()
		return v, nil
	}
	suffix := "@" + strings.ToLower(m.Domain)
	for _, u := range users {
		lu := strings.ToLower(u)
		if strings.HasSuffix(lu, suffix) && !slices.ContainsFunc(accounts, func(a store.MailAccount) bool { return a.Address == lu }) {
			v.Others = append(v.Others, lu)
		}
	}
	slices.Sort(v.Others)
	for i := range v.Accounts {
		on := hasUser(users, v.Accounts[i].Address)
		v.Accounts[i].OnPurelymail = &on
	}
	return v, nil
}

func (s *srv) handleListMailAccounts(w http.ResponseWriter, r *http.Request) {
	m, ok := s.pathMailDomain(w, r)
	if !ok {
		return
	}
	v, err := s.accountsView(r.Context(), m.ID)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleCreateMailAccounts makes each named account at Purelymail and saves
// it. Each name gets its own result, so one failure doesn't stop the rest.
func (s *srv) handleCreateMailAccounts(w http.ResponseWriter, r *http.Request) {
	m, ok := s.pathMailDomain(w, r)
	if !ok {
		return
	}
	var req mailAccountsBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Names) == 0 || len(req.Names) > 50 {
		s.storeError(w, store.ValidationError{"name": "name at least one account (e.g. info)"})
		return
	}
	ctx := r.Context()
	password := req.Password
	if password != "" {
		if s.storeError(w, store.CheckMailPassword(password)) {
			return
		}
	} else {
		shared, err := s.store.MailDomainPassword(ctx, m.ID, s.box)
		if s.storeError(w, err) {
			return
		}
		if shared == "" {
			s.storeError(w, store.ValidationError{"password": "set the shared password for " + m.Domain + " first, or give the account its own"})
			return
		}
		password = shared
	}
	if !s.box.Ready() {
		s.storeError(w, store.ConflictError("CPM_SECRET_KEY isn't set, so passwords can't be stored"))
		return
	}
	pm, ok := s.needPurelymail(w, r)
	if !ok {
		return
	}
	existing, err := s.store.ListMailAccounts(ctx, m.ID)
	if s.storeError(w, err) {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	users, err := pm.ListUsers(pctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "purelymail", err.Error())
		return
	}
	user := userFrom(r).Username
	results := []mailAccountResult{}
	seen := map[string]bool{}
	for _, raw := range req.Names {
		res := mailAccountResult{Name: strings.TrimSpace(raw)}
		name, err := store.NormalizeLocalPart(raw)
		if err != nil {
			var ve store.ValidationError
			if errors.As(err, &ve) {
				res.Error = ve["name"]
			}
			results = append(results, res)
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		res.Name, res.Address = name, name+"@"+m.Domain
		if slices.ContainsFunc(existing, func(a store.MailAccount) bool { return a.LocalPart == name }) {
			res.Error = "already on the list"
			results = append(results, res)
			continue
		}
		action := "created"
		switch {
		case hasUser(users, res.Address) && !req.TakeOver:
			res.Error, res.Exists = "already exists at Purelymail; manage it here to set its password", true
			results = append(results, res)
			continue
		case hasUser(users, res.Address):
			action = "taken over"
			err = pm.SetPassword(pctx, res.Address, password)
		default:
			err = pm.CreateUser(pctx, name, m.Domain, password)
		}
		if err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		if _, err := s.store.CreateMailAccount(ctx, m.ID, name, req.Password, s.box, user); err != nil {
			s.log.Error("saving a mail account Purelymail has", "address", res.Address, "err", err)
			res.Error = "Purelymail has it, but saving it here failed: " + err.Error()
		} else {
			s.log.Info("mail account "+action, "address", res.Address, "by", user)
		}
		results = append(results, res)
	}
	v, err := s.accountsView(ctx, m.ID)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, mailAccountsResult{mailAccountsView: v, Results: results})
}

// handleSetMailDomainPassword changes the shared password, at Purelymail
// too for every account that uses it.
func (s *srv) handleSetMailDomainPassword(w http.ResponseWriter, r *http.Request) {
	m, ok := s.pathMailDomain(w, r)
	if !ok {
		return
	}
	var req mailPasswordBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.storeError(w, store.CheckMailPassword(req.Password)) {
		return
	}
	if !s.box.Ready() {
		s.storeError(w, store.ConflictError("CPM_SECRET_KEY isn't set, so passwords can't be stored"))
		return
	}
	ctx := r.Context()
	old, err := s.store.MailDomainPassword(ctx, m.ID, s.box)
	if s.storeError(w, err) {
		return
	}
	accounts, err := s.store.ListMailAccounts(ctx, m.ID)
	if s.storeError(w, err) {
		return
	}
	var shared []store.MailAccount
	for _, a := range accounts {
		if !a.OwnPassword {
			shared = append(shared, a)
		}
	}
	failed := []mailPasswordFailure{}
	var keepOld []int64
	if len(shared) > 0 && req.Password != old {
		pm, ok := s.needPurelymail(w, r)
		if !ok {
			return
		}
		pctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
		for _, a := range shared {
			if err := pm.SetPassword(pctx, a.Address, req.Password); err != nil {
				failed = append(failed, mailPasswordFailure{Address: a.Address, Error: err.Error()})
				keepOld = append(keepOld, a.ID)
			}
		}
		if len(failed) == len(shared) {
			writeError(w, http.StatusBadGateway, "purelymail",
				"Purelymail didn't change any account's password, so nothing changed: "+failed[0].Error)
			return
		}
	}
	user := userFrom(r).Username
	if s.storeError(w, s.store.SetMailDomainPassword(ctx, m.ID, req.Password, old, keepOld, s.box, user)) {
		return
	}
	s.log.Info("mail domain password changed", "domain", m.Domain, "accounts", len(shared)-len(failed), "by", user)
	v, err := s.accountsView(ctx, m.ID)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, mailPasswordResult{mailAccountsView: v, Failed: failed})
}

func (s *srv) handleRevealMailDomainPassword(w http.ResponseWriter, r *http.Request) {
	m, ok := s.pathMailDomain(w, r)
	if !ok {
		return
	}
	pw, err := s.store.MailDomainPassword(r.Context(), m.ID, s.box)
	if s.storeError(w, err) {
		return
	}
	if pw == "" {
		writeError(w, http.StatusNotFound, "not_found", m.Domain+" has no shared password yet")
		return
	}
	if err := s.store.AuditMailReveal(r.Context(), "mail_domain", m.ID, userFrom(r).Username); err != nil {
		s.log.Error("auditing a password reveal", "err", err)
	}
	writeJSON(w, http.StatusOK, revealedPassword{Password: pw})
}

func (s *srv) pathMailAccount(w http.ResponseWriter, r *http.Request) (store.MailAccount, bool) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return store.MailAccount{}, false
	}
	a, err := s.store.GetMailAccount(r.Context(), id)
	return a, !s.storeError(w, err)
}

func (s *srv) handleRevealMailAccountPassword(w http.ResponseWriter, r *http.Request) {
	a, ok := s.pathMailAccount(w, r)
	if !ok {
		return
	}
	pw, err := s.store.MailAccountPassword(r.Context(), a.ID, s.box)
	if s.storeError(w, err) {
		return
	}
	if err := s.store.AuditMailReveal(r.Context(), "mail_account", a.ID, userFrom(r).Username); err != nil {
		s.log.Error("auditing a password reveal", "err", err)
	}
	writeJSON(w, http.StatusOK, revealedPassword{Password: pw})
}

// handleSetMailAccountPassword gives one account its own password, or puts
// it back on the shared one, at Purelymail and here.
func (s *srv) handleSetMailAccountPassword(w http.ResponseWriter, r *http.Request) {
	a, ok := s.pathMailAccount(w, r)
	if !ok {
		return
	}
	var req mailPasswordBody
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	pw, own := req.Password, req.Password
	if req.UseDomain {
		shared, err := s.store.MailDomainPassword(ctx, a.DomainID, s.box)
		if s.storeError(w, err) {
			return
		}
		if shared == "" {
			s.storeError(w, store.ValidationError{"password": "the domain has no shared password yet"})
			return
		}
		pw, own = shared, ""
	} else if s.storeError(w, store.CheckMailPassword(pw)) {
		return
	}
	if !s.box.Ready() {
		s.storeError(w, store.ConflictError("CPM_SECRET_KEY isn't set, so passwords can't be stored"))
		return
	}
	pm, ok := s.needPurelymail(w, r)
	if !ok {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := pm.SetPassword(pctx, a.Address, pw); err != nil {
		writeError(w, http.StatusBadGateway, "purelymail", err.Error())
		return
	}
	if s.storeError(w, s.store.SetMailAccountPassword(ctx, a.ID, own, s.box, userFrom(r).Username)) {
		return
	}
	v, err := s.accountsView(ctx, a.DomainID)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleDeleteMailAccount deletes the mailbox at Purelymail (with its mail)
// and takes the account off the list.
func (s *srv) handleDeleteMailAccount(w http.ResponseWriter, r *http.Request) {
	a, ok := s.pathMailAccount(w, r)
	if !ok {
		return
	}
	pm, ok := s.needPurelymail(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	users, err := pm.ListUsers(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "purelymail", err.Error())
		return
	}
	if hasUser(users, a.Address) {
		if err := pm.DeleteUser(ctx, a.Address); err != nil {
			writeError(w, http.StatusBadGateway, "purelymail", err.Error())
			return
		}
	}
	user := userFrom(r).Username
	if s.storeError(w, s.store.DeleteMailAccount(r.Context(), a.ID, user)) {
		return
	}
	s.log.Info("mail account deleted", "address", a.Address, "by", user)
	w.WriteHeader(http.StatusNoContent)
}
