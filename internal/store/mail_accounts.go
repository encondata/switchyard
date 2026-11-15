package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/encondata/switchyard/internal/secrets"
)

// MailAccount is an email account (a Purelymail user) on a mail domain.
type MailAccount struct {
	ID        int64  `json:"id"`
	DomainID  int64  `json:"domain_id"`
	LocalPart string `json:"local_part"`
	Address   string `json:"address"`
	// OwnPassword is true when the account doesn't use the domain's shared
	// password.
	OwnPassword bool      `json:"own_password"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DefaultMailAccounts are the accounts almost every domain gets.
var DefaultMailAccounts = []string{"noreply", "info", "system", "alerts"}

const mailPasswordPurpose = "mail-password"

var localPartRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$`)

// NormalizeLocalPart lower-cases and checks the part of an address before
// the @ ("info" in info@example.com).
func NormalizeLocalPart(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.IndexByte(v, '@'); i >= 0 {
		v = v[:i]
	}
	if !localPartRE.MatchString(v) || strings.Contains(v, "..") {
		return "", ValidationError{"name": "use letters, digits, dots, dashes, underscores or plus (e.g. info)"}
	}
	return v, nil
}

// CheckMailPassword checks a password before it's sent to Purelymail.
func CheckMailPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < 12 || n > 128 || !utf8.ValidString(pw) || strings.ContainsFunc(pw, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ValidationError{"password": "use 12 to 128 characters (no line breaks); Generate makes a strong one"} //nolint:gosec // help text, not a credential
	}
	if strings.TrimSpace(pw) != pw {
		return ValidationError{"password": "the password can't start or end with a space"}
	}
	return nil
}

const accountCols = `a.id, a.mail_domain_id, a.local_part, d.domain, a.password_sealed != '', a.created_at, a.updated_at`

func scanAccount(sc interface{ Scan(...any) error }) (MailAccount, error) {
	var a MailAccount
	var domain string
	err := sc.Scan(&a.ID, &a.DomainID, &a.LocalPart, &domain, &a.OwnPassword, &a.CreatedAt, &a.UpdatedAt)
	a.Address = a.LocalPart + "@" + domain
	return a, err
}

// ListMailAccounts returns a domain's accounts, by name.
func (s *Store) ListMailAccounts(ctx context.Context, domainID int64) ([]MailAccount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+accountCols+` FROM mail_accounts a
		JOIN mail_domains d ON d.id = a.mail_domain_id WHERE a.mail_domain_id = ? ORDER BY a.local_part`, domainID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []MailAccount{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetMailAccount returns one account.
func (s *Store) GetMailAccount(ctx context.Context, id int64) (MailAccount, error) {
	a, err := scanAccount(s.db.QueryRowContext(ctx, `SELECT `+accountCols+` FROM mail_accounts a
		JOIN mail_domains d ON d.id = a.mail_domain_id WHERE a.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return MailAccount{}, ErrNotFound
	}
	return a, err
}

func (s *Store) openSealed(sealed string, box *secrets.Box) (string, error) {
	if sealed == "" {
		return "", nil
	}
	if !box.Ready() {
		return "", ConflictError(secrets.ErrNoKey.Error())
	}
	return box.Open(sealed, mailPasswordPurpose)
}

func seal(pw string, box *secrets.Box) (string, error) {
	if pw == "" {
		return "", nil
	}
	if !box.Ready() {
		return "", ConflictError("CPM_SECRET_KEY isn't set, so passwords can't be stored")
	}
	return box.Seal(pw, mailPasswordPurpose)
}

// MailDomainPassword decrypts a domain's shared password ("" if not set).
func (s *Store) MailDomainPassword(ctx context.Context, id int64, box *secrets.Box) (string, error) {
	var sealed string
	err := s.db.QueryRowContext(ctx, `SELECT password_sealed FROM mail_domains WHERE id = ?`, id).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return s.openSealed(sealed, box)
}

// MailAccountPassword decrypts an account's password: its own, or else the
// domain's shared one.
func (s *Store) MailAccountPassword(ctx context.Context, id int64, box *secrets.Box) (string, error) {
	var own, shared string
	err := s.db.QueryRowContext(ctx, `SELECT a.password_sealed, d.password_sealed FROM mail_accounts a
		JOIN mail_domains d ON d.id = a.mail_domain_id WHERE a.id = ?`, id).Scan(&own, &shared)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if own != "" {
		return s.openSealed(own, box)
	}
	return s.openSealed(shared, box)
}

// SetMailDomainPassword stores a domain's shared password. Accounts listed
// in keepOld had it and couldn't be changed at Purelymail, so they get the
// old password as their own and stay right. Passwords are never audited.
func (s *Store) SetMailDomainPassword(ctx context.Context, id int64, pw, old string, keepOld []int64, box *secrets.Box, by string) error {
	if err := CheckMailPassword(pw); err != nil {
		return err
	}
	sealed, err := seal(pw, box)
	if err != nil {
		return err
	}
	sealedOld, err := seal(old, box)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE mail_domains SET password_sealed = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, sealed, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	for _, a := range keepOld {
		if _, err := tx.ExecContext(ctx, `UPDATE mail_accounts SET password_sealed = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ? AND mail_domain_id = ? AND password_sealed = ''`, sealedOld, a, id); err != nil {
			return err
		}
	}
	if err := audit(ctx, tx, by, "password", "mail_domain", id, nil, map[string]any{"kept_old_password": keepOld}); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateMailAccount records an account the caller made at Purelymail. An
// empty own password means it uses the domain's shared one.
func (s *Store) CreateMailAccount(ctx context.Context, domainID int64, local, own string, box *secrets.Box, by string) (MailAccount, error) {
	local, err := NormalizeLocalPart(local)
	if err != nil {
		return MailAccount{}, err
	}
	sealed, err := seal(own, box)
	if err != nil {
		return MailAccount{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MailAccount{}, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO mail_accounts (mail_domain_id, local_part, password_sealed) VALUES (?, ?, ?)`,
		domainID, local, sealed)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return MailAccount{}, ValidationError{"name": local + " is already on the list"}
		}
		if strings.Contains(err.Error(), "FOREIGN KEY") {
			return MailAccount{}, ErrNotFound
		}
		return MailAccount{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return MailAccount{}, err
	}
	if err := audit(ctx, tx, by, "create", "mail_account", id, nil,
		map[string]any{"domain_id": domainID, "name": local, "own_password": own != ""}); err != nil {
		return MailAccount{}, err
	}
	if err := tx.Commit(); err != nil {
		return MailAccount{}, err
	}
	return s.GetMailAccount(ctx, id)
}

// SetMailAccountPassword gives an account its own password, or ("") puts it
// back on the domain's shared one.
func (s *Store) SetMailAccountPassword(ctx context.Context, id int64, own string, box *secrets.Box, by string) error {
	if own != "" {
		if err := CheckMailPassword(own); err != nil {
			return err
		}
	}
	sealed, err := seal(own, box)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE mail_accounts SET password_sealed = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, sealed, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := audit(ctx, tx, by, "password", "mail_account", id, nil, map[string]bool{"own_password": own != ""}); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteMailAccount takes an account off the list (the caller deleted it at
// Purelymail).
func (s *Store) DeleteMailAccount(ctx context.Context, id int64, by string) error {
	a, err := s.GetMailAccount(ctx, id)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_accounts WHERE id = ?`, id); err != nil {
		return err
	}
	if err := audit(ctx, tx, by, "delete", "mail_account", id, map[string]string{"address": a.Address}, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// AuditMailReveal logs that someone was shown a password.
func (s *Store) AuditMailReveal(ctx context.Context, entity string, id int64, by string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := audit(ctx, tx, by, "reveal_password", entity, id, nil, nil); err != nil {
		return err
	}
	return tx.Commit()
}
