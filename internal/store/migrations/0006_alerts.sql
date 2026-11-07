-- In-app alerts (spec F2, F7; CPM-24). One open alert per (kind, subject).
CREATE TABLE alerts (
    id           INTEGER PRIMARY KEY,
    kind         TEXT NOT NULL,
    subject      TEXT NOT NULL,
    message      TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at  TIMESTAMP
);
CREATE UNIQUE INDEX alerts_open ON alerts (kind, subject) WHERE resolved_at IS NULL;
CREATE INDEX alerts_created_at ON alerts (created_at);
