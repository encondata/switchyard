-- Email accounts (Purelymail users) on mail domains. Each domain has one
-- shared password its accounts use unless an account has its own. Passwords
-- are sealed with CPM_SECRET_KEY, so they can be shown again.
ALTER TABLE mail_domains ADD COLUMN password_sealed TEXT NOT NULL DEFAULT '';

CREATE TABLE mail_accounts (
    id              INTEGER PRIMARY KEY,
    mail_domain_id  INTEGER NOT NULL REFERENCES mail_domains (id) ON DELETE RESTRICT,
    local_part      TEXT NOT NULL COLLATE NOCASE,
    password_sealed TEXT NOT NULL DEFAULT '', -- '' = uses the domain's shared password
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (mail_domain_id, local_part)
);
