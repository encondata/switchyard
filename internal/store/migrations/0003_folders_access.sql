CREATE TABLE folders (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    parent_id  INTEGER REFERENCES folders (id) ON DELETE RESTRICT,
    sort       INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Names are unique among siblings (COALESCE puts top-level folders together).
CREATE UNIQUE INDEX folders_parent_name ON folders (COALESCE(parent_id, 0), name COLLATE NOCASE);

ALTER TABLE hosts ADD COLUMN folder_id INTEGER REFERENCES folders (id) ON DELETE RESTRICT;
CREATE INDEX hosts_folder_id ON hosts (folder_id);

CREATE TABLE access_policies (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    mode       TEXT NOT NULL CHECK (mode IN ('allow_only', 'deny')),
    response   TEXT NOT NULL DEFAULT '403' CHECK (response IN ('403', 'abort')),
    rules      TEXT NOT NULL DEFAULT '[]', -- JSON array of IPs / CIDRs
    notes      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE folder_policies (
    folder_id INTEGER NOT NULL REFERENCES folders (id) ON DELETE CASCADE,
    policy_id INTEGER NOT NULL REFERENCES access_policies (id) ON DELETE RESTRICT,
    PRIMARY KEY (folder_id, policy_id)
);

CREATE TABLE host_policies (
    host_id   INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    policy_id INTEGER NOT NULL REFERENCES access_policies (id) ON DELETE RESTRICT,
    PRIMARY KEY (host_id, policy_id)
);

-- Addresses that are never blocked by any rule (spec F4 step 1).
CREATE TABLE never_ban (
    cidr       TEXT PRIMARY KEY,
    note       TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
