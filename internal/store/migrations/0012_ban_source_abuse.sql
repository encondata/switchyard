-- Bans can also come from the abuse rules (too many rate-limited, blocked
-- or not-found responses). SQLite can't change a CHECK in place, so the
-- table is rebuilt with every existing row kept.
CREATE TABLE bans_new (
    id         INTEGER PRIMARY KEY,
    cidr       TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL CHECK (source IN ('honeypot', 'manual', 'crowdsec', 'abuse')),
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,          -- NULL = until removed
    removed_at TIMESTAMP,          -- lifted early
    hit_count  INTEGER NOT NULL DEFAULT 0
);
INSERT INTO bans_new (id, cidr, reason, source, created_by, created_at, expires_at, removed_at, hit_count)
    SELECT id, cidr, reason, source, created_by, created_at, expires_at, removed_at, hit_count FROM bans;
DROP TABLE bans;
ALTER TABLE bans_new RENAME TO bans;
CREATE INDEX bans_cidr ON bans (cidr);
CREATE INDEX bans_active ON bans (removed_at, expires_at);
