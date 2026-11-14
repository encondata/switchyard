package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/encondata/switchyard/internal/cloudflare"
	"github.com/encondata/switchyard/internal/purelymail"
	"github.com/encondata/switchyard/internal/store"
)

// Mail domains: Purelymail's DNS records, kept in Cloudflare.

type (
	// mailSettingsBody changes the Purelymail settings. A new api_key is
	// checked with Purelymail, and the ownership proof is fetched with it.
	mailSettingsBody struct {
		Ownership *string `json:"ownership,omitempty"` // nil keeps it
		APIKey    string  `json:"api_key,omitempty"`   // "" keeps the stored key
		ClearKey  bool    `json:"clear_key,omitempty"`
	}
	mailSettings struct {
		Ownership string `json:"ownership"`
		KeySet    bool   `json:"key_set"`
	}
	// pmStatus is Purelymail's own view of a domain (with an API key).
	pmStatus struct {
		Added bool                   `json:"added"`
		DNS   *purelymail.DNSSummary `json:"dns,omitempty"`
		Error string                 `json:"error,omitempty"`
	}
	mailDomainBody struct {
		Domain        string `json:"domain"`
		DNSProviderID int64  `json:"dns_provider_id"`
	}
	mailApplyBody struct {
		// Keys of conflicting records to replace (deleting what's in the
		// way), e.g. ["mx", "spf"]. Missing records are always added.
		Replace []string `json:"replace"`
	}
	// mailCheck is a domain and how its zone stands against Purelymail's
	// records.
	mailCheck struct {
		Domain  store.MailDomain    `json:"domain"`
		Records []purelymail.Item   `json:"records"`
		Changes []purelymail.Change `json:"changes,omitempty"`
		// Purelymail is set when an API key is stored.
		Purelymail *pmStatus `json:"purelymail,omitempty"`
	}
)

func (s *srv) mailSettings(ctx context.Context) (mailSettings, error) {
	v, err := s.store.PurelymailOwnership(ctx)
	if err != nil {
		return mailSettings{}, err
	}
	set, err := s.store.PurelymailKeySet(ctx)
	return mailSettings{Ownership: v, KeySet: set}, err
}

func (s *srv) handleGetMailSettings(w http.ResponseWriter, r *http.Request) {
	ms, err := s.mailSettings(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, ms)
}

func (s *srv) handlePutMailSettings(w http.ResponseWriter, r *http.Request) {
	var req mailSettingsBody
	if !decodeJSON(w, r, &req) {
		return
	}
	user := userFrom(r).Username
	ctx := r.Context()
	switch {
	case req.APIKey != "":
		key, err := store.CleanPurelymailKey(req.APIKey)
		if s.storeError(w, err) {
			return
		}
		if !s.box.Ready() {
			s.storeError(w, store.ConflictError("CPM_SECRET_KEY isn't set, so the API key can't be stored"))
			return
		}
		// A key that works can fetch the ownership code: that checks it
		// and saves pasting the code.
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		code, err := purelymail.Client{Token: key}.OwnershipCode(cctx)
		cancel()
		if err != nil {
			msg := err.Error()
			var pe *purelymail.APIError
			if errors.As(err, &pe) && pe.BadKey() {
				msg = "Purelymail didn't accept this API key"
			}
			s.storeError(w, store.ValidationError{"api_key": msg})
			return
		}
		if s.storeError(w, s.store.SavePurelymailKey(ctx, key, s.box, user)) {
			return
		}
		req.Ownership = &code
	case req.ClearKey:
		if s.storeError(w, s.store.SavePurelymailKey(ctx, "", s.box, user)) {
			return
		}
	}
	if req.Ownership != nil {
		if _, err := s.store.SavePurelymailOwnership(ctx, *req.Ownership, user); s.storeError(w, err) {
			return
		}
	}
	ms, err := s.mailSettings(ctx)
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, ms)
}

func (s *srv) handleListMailDomains(w http.ResponseWriter, r *http.Request) {
	ds, err := s.store.ListMailDomains(r.Context())
	if s.storeError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, ds)
}

// handleCreateMailDomain finds the domain's zone on the provider, saves the
// domain and checks its records (nothing in DNS changes yet).
func (s *srv) handleCreateMailDomain(w http.ResponseWriter, r *http.Request) {
	var req mailDomainBody
	if !decodeJSON(w, r, &req) {
		return
	}
	domain, err := store.NormalizeMailDomain(req.Domain)
	if s.storeError(w, err) {
		return
	}
	if req.DNSProviderID == 0 {
		s.storeError(w, store.ValidationError{"dns_provider_id": "choose a DNS provider"})
		return
	}
	tok, err := s.store.DNSToken(r.Context(), req.DNSProviderID, s.box)
	if errors.Is(err, store.ErrNotFound) {
		s.storeError(w, store.ValidationError{"dns_provider_id": "choose a DNS provider"})
		return
	} else if s.storeError(w, err) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	zone, err := cloudflare.FindZone(ctx, tok, domain)
	if errors.Is(err, cloudflare.ErrNoZone) {
		s.storeError(w, store.ValidationError{"domain": "this provider’s token can’t see a Cloudflare zone for " + domain + " (it needs Zone → Zone → Read and Zone → DNS → Edit)"})
		return
	} else if err != nil {
		writeError(w, http.StatusBadGateway, "cloudflare", err.Error())
		return
	}
	m, err := s.store.CreateMailDomain(r.Context(), store.MailDomain{
		Domain: domain, DNSProviderID: req.DNSProviderID, ZoneID: zone.ID, ZoneName: zone.Name,
	}, userFrom(r).Username)
	if s.storeError(w, err) {
		return
	}
	check, err := s.checkMail(ctx, m, tok)
	if err != nil {
		// Saved; the check can be run again from the list.
		check = mailCheck{Domain: check.Domain, Records: []purelymail.Item{}}
	}
	writeJSON(w, http.StatusCreated, check)
}

// handleCheckMailDomain compares the zone's records with Purelymail's.
func (s *srv) handleCheckMailDomain(w http.ResponseWriter, r *http.Request) {
	m, tok, ok := s.mailDomain(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	check, err := s.checkMail(ctx, m, tok)
	if err != nil {
		writeError(w, http.StatusBadGateway, "cloudflare", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, check)
}

// handleApplyMailDomain adds missing records and replaces the conflicting
// ones it's told to. The plan is worked out again here from the zone as it
// is now; the client only says which conflicts to replace.
func (s *srv) handleApplyMailDomain(w http.ResponseWriter, r *http.Request) {
	m, tok, ok := s.mailDomain(w, r)
	if !ok {
		return
	}
	var req mailApplyBody
	if !decodeJSON(w, r, &req) {
		return
	}
	replace := map[string]bool{}
	for _, k := range req.Replace {
		replace[k] = true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	before, err := s.checkMail(ctx, m, tok)
	if err != nil {
		writeError(w, http.StatusBadGateway, "cloudflare", err.Error())
		return
	}
	changes := purelymail.Apply(ctx, before.Records, replace, zoneDNS{token: tok, zone: m.ZoneID})
	user := userFrom(r).Username
	if len(changes) > 0 {
		if err := s.store.AuditMailRecords(r.Context(), m.ID, user, map[string]any{"domain": m.Domain, "changes": changes}); err != nil {
			s.log.Error("auditing mail records", "err", err)
		}
		s.log.Info("mail records changed", "domain", m.Domain, "changes", len(changes), "by", user)
	}
	after, err := s.checkMail(ctx, m, tok)
	if err != nil {
		writeError(w, http.StatusBadGateway, "cloudflare", "records changed, but checking them again failed: "+err.Error())
		return
	}
	after.Changes = changes
	writeJSON(w, http.StatusOK, after)
}

func (s *srv) handleDeleteMailDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if s.storeError(w, s.store.DeleteMailDomain(r.Context(), id, userFrom(r).Username)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// mailDomain loads the domain in the path and its provider's token.
func (s *srv) mailDomain(w http.ResponseWriter, r *http.Request) (store.MailDomain, string, bool) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return store.MailDomain{}, "", false
	}
	m, err := s.store.GetMailDomain(r.Context(), id)
	if s.storeError(w, err) {
		return m, "", false
	}
	tok, err := s.store.DNSToken(r.Context(), m.DNSProviderID, s.box)
	if s.storeError(w, err) {
		return m, "", false
	}
	return m, tok, true
}

// checkMail lists the zone's records, plans against them and saves the
// domain's status.
func (s *srv) checkMail(ctx context.Context, m store.MailDomain, tok string) (mailCheck, error) {
	ownership, err := s.store.PurelymailOwnership(ctx)
	if err != nil {
		return mailCheck{Domain: m}, err
	}
	now := time.Now()
	recs, err := cloudflare.ListRecords(ctx, tok, m.ZoneID)
	if err != nil {
		_ = s.store.SetMailStatus(ctx, m.ID, "error", err.Error(), now)
		m, _ = s.store.GetMailDomain(ctx, m.ID)
		return mailCheck{Domain: m}, err
	}
	items := purelymail.Plan(m.Domain, ownership, recs)
	if err := s.store.SetMailStatus(ctx, m.ID, purelymail.Status(items), "", now); err != nil {
		return mailCheck{Domain: m}, err
	}
	if m, err = s.store.GetMailDomain(ctx, m.ID); err != nil {
		return mailCheck{}, err
	}
	check := mailCheck{Domain: m, Records: items}
	if pm, ok := s.purelymailClient(ctx); ok {
		check.Purelymail = &pmStatus{}
		if d, err := pm.FindDomain(ctx, m.Domain); err != nil {
			check.Purelymail.Error = err.Error()
		} else if d != nil {
			check.Purelymail.Added, check.Purelymail.DNS = true, &d.DNSSummary
		}
	}
	return check, nil
}

// purelymailClient is a client with the stored API key, if there is one.
func (s *srv) purelymailClient(ctx context.Context) (purelymail.Client, bool) {
	key, err := s.store.PurelymailKey(ctx, s.box)
	if err != nil {
		s.log.Warn("reading the Purelymail API key", "err", err)
		return purelymail.Client{}, false
	}
	return purelymail.Client{Token: key}, key != ""
}

// handlePurelymailDomain adds the domain to the Purelymail account, or, if
// it's there already, asks Purelymail to check its DNS again.
func (s *srv) handlePurelymailDomain(w http.ResponseWriter, r *http.Request) {
	m, tok, ok := s.mailDomain(w, r)
	if !ok {
		return
	}
	pm, ok := s.purelymailClient(r.Context())
	if !ok {
		writeError(w, http.StatusConflict, "conflict", "Save a Purelymail API key first.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	d, err := pm.FindDomain(ctx, m.Domain)
	if err != nil {
		writeError(w, http.StatusBadGateway, "purelymail", err.Error())
		return
	}
	action := "purelymail_add"
	if d == nil {
		err = pm.AddDomain(ctx, m.Domain)
	} else {
		action = "purelymail_recheck"
		err = pm.RecheckDNS(ctx, m.Domain)
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "purelymail", err.Error())
		return
	}
	user := userFrom(r).Username
	if err := s.store.AuditMail(r.Context(), m.ID, user, action, map[string]string{"domain": m.Domain}); err != nil {
		s.log.Error("auditing mail domain", "err", err)
	}
	s.log.Info("purelymail domain", "domain", m.Domain, "action", action, "by", user)
	check, err := s.checkMail(ctx, m, tok)
	if err != nil {
		writeError(w, http.StatusBadGateway, "cloudflare", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, check)
}

// zoneDNS changes records in one Cloudflare zone.
type zoneDNS struct{ token, zone string }

func (z zoneDNS) Create(ctx context.Context, r cloudflare.Record) (cloudflare.Record, error) {
	return cloudflare.CreateRecord(ctx, z.token, z.zone, r)
}

func (z zoneDNS) Delete(ctx context.Context, id string) error {
	return cloudflare.DeleteRecord(ctx, z.token, z.zone, id)
}
