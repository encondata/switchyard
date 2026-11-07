-- Honeypot and bans (spec F4 step 2, F6; CPM-28..31).
CREATE TABLE trap_paths (
    id         INTEGER PRIMARY KEY,
    pattern    TEXT NOT NULL UNIQUE,  -- Caddy path matcher pattern, e.g. /.git/*
    score      INTEGER NOT NULL DEFAULT 10,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO trap_paths (pattern) VALUES
    ('/.env'), ('/.env.*'), ('/.git/*'), ('/wp-login.php'), ('/xmlrpc.php'),
    ('/phpmyadmin*'), ('/vendor/phpunit/*'), ('/cgi-bin/*'), ('/actuator*'),
    ('/server-status'), ('/.aws/credentials');

-- Trap paths a host should serve normally (false positives).
ALTER TABLE hosts ADD COLUMN trap_exceptions TEXT NOT NULL DEFAULT '[]';

CREATE TABLE bans (
    id         INTEGER PRIMARY KEY,
    cidr       TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL CHECK (source IN ('honeypot', 'manual', 'crowdsec')),
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,          -- NULL = until removed
    removed_at TIMESTAMP,          -- lifted early
    hit_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX bans_cidr ON bans (cidr);
CREATE INDEX bans_active ON bans (removed_at, expires_at);

-- Points per honeypot hit, summed over a sliding 24 hours.
CREATE TABLE honeypot_points (
    ip     TEXT NOT NULL,
    at     TIMESTAMP NOT NULL,
    points INTEGER NOT NULL
);
CREATE INDEX honeypot_points_ip_at ON honeypot_points (ip, at);
