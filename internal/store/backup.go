package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Backup writes a consistent copy of the database to dest (which must not
// exist). DNS tokens stay sealed, so restoring needs the same
// CPM_SECRET_KEY.
func (s *Store) Backup(ctx context.Context, dest string) error {
	_, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, dest)
	return err
}

// ValidateBackup checks that path is a CPM database this version can use:
// a SQLite file whose applied migrations are all ones this build knows.
func ValidateBackup(ctx context.Context, path string) error {
	f, err := os.Open(path) //nolint:gosec // path is CPM's own temp file
	if err != nil {
		return err
	}
	head := make([]byte, 16)
	_, err = f.Read(head)
	_ = f.Close()
	if err != nil || !bytes.Equal(head, []byte("SQLite format 3\x00")) {
		return ConflictError("That file isn't a CPM backup (not a SQLite database).")
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	known := map[string]bool{}
	names, _ := fs.Glob(migrations, "migrations/*.sql")
	for _, n := range names {
		known[n] = true
	}
	rows, err := db.QueryContext(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return ConflictError("That file isn't a CPM backup (no schema_migrations table).")
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		if !known[n] {
			return ConflictError(fmt.Sprintf("The backup comes from a newer CPM (migration %s). Upgrade CPM first.", strings.TrimPrefix(n, "migrations/")))
		}
		count++
	}
	if count == 0 {
		return ConflictError("That file isn't a CPM backup (no migrations applied).")
	}
	var users int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users); err != nil || users == 0 {
		return ConflictError("The backup has no users, so nobody could sign in after restoring it.")
	}
	return nil
}
