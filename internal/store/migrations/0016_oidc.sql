-- Sign in with HackSpaceLabs (Keycloak OpenID Connect), PLAN.md work package 2.
-- Accounts made by that sign-in have auth_source 'oidc' and the Keycloak user id in oidc_subject. Their
-- password_hash holds a marker that can never match a password (SQLite can't drop NOT NULL in place).
ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc'));
ALTER TABLE users ADD COLUMN oidc_subject TEXT;
ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX users_oidc_subject ON users (oidc_subject) WHERE oidc_subject IS NOT NULL;

-- Sessions started through HackSpaceLabs keep Keycloak's tokens (sealed with CPM_SECRET_KEY) so they can
-- be rechecked, and end when Keycloak's session does.
ALTER TABLE sessions ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE sessions ADD COLUMN idp_sid TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN idp_tokens TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN idp_checked_at TIMESTAMP;

-- Sign-ins in progress: one row per trip to Keycloak, used once, gone after 10 minutes.
CREATE TABLE oidc_flows (
    state_hash TEXT PRIMARY KEY,
    nonce      TEXT NOT NULL,
    verifier   TEXT NOT NULL,
    next_path  TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
