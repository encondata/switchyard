-- API keys for other programs (CRUD over the REST API). Each key has its
-- own list of operations it may call. Only a SHA-256 of the token is kept;
-- the token itself is shown once, when the key is made.
CREATE TABLE api_keys (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    permissions  TEXT NOT NULL DEFAULT '[]',
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   TIMESTAMP,
    last_used_at TIMESTAMP,
    last_used_ip TEXT NOT NULL DEFAULT '',
    revoked_at   TIMESTAMP
);
