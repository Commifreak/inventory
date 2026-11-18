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

// User is a web UI user. Superadmins may do everything; other users manage
// the devices and enrollment tokens of their areas.
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
	Superadmin         bool
}

const userCols = `id, username, password_hash, oidc_subject, email, must_change_password, disabled, created_at, last_login_at, superadmin`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var pw, sub, email sql.NullString
	var created int64
	var last sql.NullInt64
	if err := row.Scan(&u.ID, &u.Username, &pw, &sub, &email, &u.MustChangePassword, &u.Disabled, &created, &last, &u.Superadmin); err != nil {
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
	res, err := s.DB.ExecContext(ctx, `INSERT INTO users(username, password_hash, oidc_subject, email, must_change_password, disabled, created_at, superadmin) VALUES(?,?,?,?,?,?,?,?)`,
		u.Username, nullStr(u.PasswordHash), nullStr(u.OIDCSubject), nullStr(u.Email), u.MustChangePassword, u.Disabled, time.Now().Unix(), u.Superadmin)
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

func (s *Store) SetSuperadmin(ctx context.Context, id int64, on bool) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET superadmin=? WHERE id=?`, on, id)
	return err
}

// CountActiveSuperadmins counts enabled superadmins other than exceptID.
func (s *Store) CountActiveSuperadmins(ctx context.Context, exceptID int64) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE superadmin=1 AND disabled=0 AND id<>?`, exceptID).Scan(&n)
	return n, err
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
	// ImpersonatorID is the superadmin who signed in as UserID (0 = none).
	ImpersonatorID int64
}

func (s *Store) CreateSession(ctx context.Context, sess *Session, ip, ua string) error {
	var imp any
	if sess.ImpersonatorID != 0 {
		imp = sess.ImpersonatorID
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(id_hash, user_id, csrf, created_at, expires_at, ip, user_agent, impersonator_id) VALUES(?,?,?,?,?,?,?,?)`,
		sess.IDHash, sess.UserID, sess.CSRF, sess.CreatedAt.Unix(), sess.ExpiresAt.Unix(), ip, ua, imp)
	return err
}

func (s *Store) SessionByHash(ctx context.Context, h string) (*Session, error) {
	var sess Session
	var c, e int64
	var imp sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `SELECT id_hash, user_id, csrf, created_at, expires_at, impersonator_id FROM sessions WHERE id_hash=?`, h).
		Scan(&sess.IDHash, &sess.UserID, &sess.CSRF, &c, &e, &imp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt, sess.ExpiresAt = time.Unix(c, 0), time.Unix(e, 0)
	sess.ImpersonatorID = imp.Int64
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
	AreaID   int64 // 0 = global
}

// Audit records a global entry (only visible to superadmins).
func (s *Store) Audit(ctx context.Context, user, action, details string) {
	s.AuditArea(ctx, 0, user, action, details)
}

// AuditArea records an entry belonging to an area (0 = global).
func (s *Store) AuditArea(ctx context.Context, areaID int64, user, action, details string) {
	var area any
	if areaID != 0 {
		area = areaID
	}
	_, _ = s.DB.ExecContext(ctx, `INSERT INTO audit_log(ts, username, action, details, area_id) VALUES(?,?,?,?,?)`, time.Now().Unix(), user, action, details, area)
}

// ListAudit returns the newest entries. With all=false only entries of the
// given areas are returned.
func (s *Store) ListAudit(ctx context.Context, limit int, all bool, areas []int64) ([]AuditEntry, error) {
	q, args := `SELECT id, ts, COALESCE(username,''), action, COALESCE(details,''), COALESCE(area_id,0) FROM audit_log`, []any{}
	if !all {
		if len(areas) == 0 {
			return nil, nil
		}
		q += ` WHERE area_id IN (` + placeholders(len(areas)) + `)`
		for _, a := range areas {
			args = append(args, a)
		}
	}
	rows, err := s.DB.QueryContext(ctx, q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		var ts int64
		if err := rows.Scan(&a.ID, &ts, &a.Username, &a.Action, &a.Details, &a.AreaID); err != nil {
			return nil, err
		}
		a.Time = time.Unix(ts, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}
