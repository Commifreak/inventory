package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// User is a web UI user. All users are administrators.
type User struct {
	ID                 int64
	Username           string
	PasswordHash       string
	OIDCSubject        string
	Email              string
	MustChangePassword bool
	Disabled           bool
	CreatedAt          time.Time
	LastLoginAt        time.Time
}

const userCols = `id, username, password_hash, oidc_subject, email, must_change_password, disabled, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var pw, sub, email sql.NullString
	var created int64
	var last sql.NullInt64
	if err := row.Scan(&u.ID, &u.Username, &pw, &sub, &email, &u.MustChangePassword, &u.Disabled, &created, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.PasswordHash, u.OIDCSubject, u.Email = pw.String, sub.String, email.String
	u.CreatedAt = time.Unix(created, 0)
	u.LastLoginAt = tu(last)
	return &u, nil
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id))
}

func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username=?`, name))
}

func (s *Store) UserBySubject(ctx context.Context, sub string) (*User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE oidc_subject=?`, sub))
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, u *User) error {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO users(username, password_hash, oidc_subject, email, must_change_password, disabled, created_at) VALUES(?,?,?,?,?,?,?)`,
		u.Username, nullStr(u.PasswordHash), nullStr(u.OIDCSubject), nullStr(u.Email), u.MustChangePassword, u.Disabled, time.Now().Unix())
	if err != nil {
		return err
	}
	u.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) SetPassword(ctx context.Context, id int64, hash string, mustChange bool) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET password_hash=?, must_change_password=? WHERE id=?`, nullStr(hash), mustChange, id)
	return err
}

func (s *Store) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET disabled=? WHERE id=?`, disabled, id)
	return err
}

func (s *Store) UpdateUserOIDC(ctx context.Context, id int64, sub, email string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET oidc_subject=?, email=? WHERE id=?`, nullStr(sub), nullStr(email), id)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) TouchLogin(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET last_login_at=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

// ---------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------

type Session struct {
	IDHash    string
	UserID    int64
	CSRF      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, sess *Session, ip, ua string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(id_hash, user_id, csrf, created_at, expires_at, ip, user_agent) VALUES(?,?,?,?,?,?,?)`,
		sess.IDHash, sess.UserID, sess.CSRF, sess.CreatedAt.Unix(), sess.ExpiresAt.Unix(), ip, ua)
	return err
}

func (s *Store) SessionByHash(ctx context.Context, h string) (*Session, error) {
	var sess Session
	var c, e int64
	err := s.DB.QueryRowContext(ctx, `SELECT id_hash, user_id, csrf, created_at, expires_at FROM sessions WHERE id_hash=?`, h).
		Scan(&sess.IDHash, &sess.UserID, &sess.CSRF, &c, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt, sess.ExpiresAt = time.Unix(c, 0), time.Unix(e, 0)
	return &sess, nil
}

func (s *Store) ExtendSession(ctx context.Context, h string, exp time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET expires_at=? WHERE id_hash=?`, exp.Unix(), h)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, h string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, h)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID int64, exceptHash string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=? AND id_hash<>?`, userID, exceptHash)
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<?`, time.Now().Unix())
	return err
}

// ---------------------------------------------------------------------------
// settings (JSON values)
// ---------------------------------------------------------------------------

// GetSetting decodes the JSON value of key into v. Returns false if unset.
func (s *Store) GetSetting(ctx context.Context, key string, v any) (bool, error) {
	var raw string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

func (s *Store) PutSetting(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, string(b))
	return err
}

// ---------------------------------------------------------------------------
// audit log
// ---------------------------------------------------------------------------

type AuditEntry struct {
	ID       int64
	Time     time.Time
	Username string
	Action   string
	Details  string
}

func (s *Store) Audit(ctx context.Context, user, action, details string) {
	_, _ = s.DB.ExecContext(ctx, `INSERT INTO audit_log(ts, username, action, details) VALUES(?,?,?,?)`, time.Now().Unix(), user, action, details)
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, ts, COALESCE(username,''), action, COALESCE(details,'') FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var ts int64
		if err := rows.Scan(&a.ID, &ts, &a.Username, &a.Action, &a.Details); err != nil {
			return nil, err
		}
		a.Time = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}
