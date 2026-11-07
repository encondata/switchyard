-- Per-host / per-folder rate limits by client IP (CPM-26). 0 events = off
-- (hosts then inherit the nearest folder's limit).
ALTER TABLE hosts ADD COLUMN rate_limit_events INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN rate_limit_window INTEGER NOT NULL DEFAULT 60;
ALTER TABLE folders ADD COLUMN rate_limit_events INTEGER NOT NULL DEFAULT 0;
ALTER TABLE folders ADD COLUMN rate_limit_window INTEGER NOT NULL DEFAULT 60;
