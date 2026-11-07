CREATE TABLE dns_providers (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    type        TEXT NOT NULL CHECK (type IN ('cloudflare')),
    credentials TEXT NOT NULL, -- sealed with CPM_SECRET_KEY (internal/secrets)
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- tls_mode keeps its original CHECK; the DNS challenge is stored as
-- tls_mode 'auto' + acme_challenge 'dns' and shown to clients as "dns".
ALTER TABLE hosts ADD COLUMN acme_challenge TEXT NOT NULL DEFAULT 'http' CHECK (acme_challenge IN ('http', 'dns'));
ALTER TABLE hosts ADD COLUMN dns_provider_id INTEGER REFERENCES dns_providers (id) ON DELETE RESTRICT;
ALTER TABLE folders ADD COLUMN dns_provider_id INTEGER REFERENCES dns_providers (id) ON DELETE RESTRICT;
