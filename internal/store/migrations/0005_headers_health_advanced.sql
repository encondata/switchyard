-- Custom headers (JSON arrays of {op, name, value}), upstream health checks
-- and the admin-only advanced route snippet (CPM-11, 12, 13, 16).
ALTER TABLE hosts ADD COLUMN request_headers TEXT NOT NULL DEFAULT '[]';
ALTER TABLE hosts ADD COLUMN response_headers TEXT NOT NULL DEFAULT '[]';
ALTER TABLE hosts ADD COLUMN health_check_path TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN health_check_interval INTEGER NOT NULL DEFAULT 30;
ALTER TABLE hosts ADD COLUMN advanced_json TEXT NOT NULL DEFAULT '';
ALTER TABLE folders ADD COLUMN request_headers TEXT NOT NULL DEFAULT '[]';
ALTER TABLE folders ADD COLUMN response_headers TEXT NOT NULL DEFAULT '[]';
