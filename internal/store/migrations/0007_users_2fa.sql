-- User management and TOTP two-factor sign-in (CPM-18, CPM-25).
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';    -- sealed with CPM_SECRET_KEY
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0; -- blocks code reuse
ALTER TABLE users ADD COLUMN backup_codes TEXT NOT NULL DEFAULT '[]';  -- JSON array of bcrypt hashes

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Half-finished sign-ins waiting for a second factor.
CREATE TABLE login_challenges (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    attempts   INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL
);
