CREATE TABLE hosts (
    id             INTEGER PRIMARY KEY,
    type           TEXT NOT NULL CHECK (type IN ('proxy', 'redirect', '404')),
    enabled        INTEGER NOT NULL DEFAULT 1,
    upstreams      TEXT NOT NULL DEFAULT '[]', -- JSON array of upstreams
    load_balancing TEXT NOT NULL DEFAULT 'round_robin',
    tls_mode       TEXT NOT NULL DEFAULT 'auto' CHECK (tls_mode IN ('auto', 'internal', 'off')),
    force_https    INTEGER NOT NULL DEFAULT 1,
    hsts           INTEGER NOT NULL DEFAULT 0,
    compression    INTEGER NOT NULL DEFAULT 1,
    redirect_to    TEXT NOT NULL DEFAULT '',
    redirect_code  INTEGER NOT NULL DEFAULT 301,
    preserve_path  INTEGER NOT NULL DEFAULT 1,
    notes          TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One row per domain; the primary key stops two hosts claiming a domain.
CREATE TABLE host_domains (
    domain   TEXT PRIMARY KEY COLLATE NOCASE,
    host_id  INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    position INTEGER NOT NULL
);
CREATE INDEX host_domains_host_id ON host_domains (host_id);

CREATE TABLE config_versions (
    n          INTEGER PRIMARY KEY AUTOINCREMENT,
    json       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    applied_by TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    result     TEXT NOT NULL CHECK (result IN ('ok', 'failed')),
    error      TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY,
    at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username  TEXT NOT NULL,
    action    TEXT NOT NULL,
    entity    TEXT NOT NULL,
    entity_id TEXT NOT NULL DEFAULT '',
    before    TEXT NOT NULL DEFAULT '',
    after     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at ON audit_log (at);
