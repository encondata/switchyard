-- Per-user display preferences, such as the UI accent color ('' = default).
CREATE TABLE user_prefs (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    accent  TEXT NOT NULL DEFAULT ''
);
