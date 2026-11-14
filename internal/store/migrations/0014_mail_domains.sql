-- Mail domains: domains whose mail is at Purelymail, with their DNS on a
-- Cloudflare provider. Switchyard checks and adds Purelymail's records.
CREATE TABLE mail_domains (
    id              INTEGER PRIMARY KEY,
    domain          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    dns_provider_id INTEGER NOT NULL REFERENCES dns_providers (id) ON DELETE RESTRICT,
    zone_id         TEXT NOT NULL,
    zone_name       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT '', -- ok, incomplete, conflict, error ('' = not checked)
    status_detail   TEXT NOT NULL DEFAULT '',
    checked_at      TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
