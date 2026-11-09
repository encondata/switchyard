-- Shared wildcard certificates: one *.domain certificate (DNS challenge)
-- covers every host one level under it, so those hosts get no certificate
-- of their own and never appear in Certificate Transparency logs.
CREATE TABLE wildcard_certs (
    id              INTEGER PRIMARY KEY,
    domain          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    dns_provider_id INTEGER NOT NULL REFERENCES dns_providers (id),
    include_apex    INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- A host on hold serves the honeypot decoy (while its new certificate draws
-- scanners from the CT logs) until hold_until, then goes live by itself.
ALTER TABLE hosts ADD COLUMN hold_until TIMESTAMP;
