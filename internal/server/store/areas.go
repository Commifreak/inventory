package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"
)

// Area groups devices, enrollment tokens and users.
type Area struct {
	ID         int64
	Name       string
	OIDCGroup  string
	Recipients []string // alert mail recipients of this area
	CreatedAt  time.Time
}

// Membership sources.
const (
	MemberManual = "manual" // assigned in the UI
	MemberOIDC   = "oidc"   // from the OIDC group, synchronised at login
)

// Membership is a user's membership in an area.
type Membership struct {
	UserID int64
	AreaID int64
	Source string
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

const areaCols = `id, name, oidc_group, recipients, created_at`

func scanArea(row interface{ Scan(...any) error }) (*Area, error) {
	var a Area
	var group sql.NullString
	var rcpt string
	var created int64
	if err := row.Scan(&a.ID, &a.Name, &group, &rcpt, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.OIDCGroup = group.String
	if rcpt != "" {
		a.Recipients = strings.Split(rcpt, ",")
	}
	a.CreatedAt = time.Unix(created, 0)
	return &a, nil
}

func (s *Store) ListAreas(ctx context.Context) ([]Area, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+areaCols+` FROM areas ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Area
	for rows.Next() {
		a, err := scanArea(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) AreaByID(ctx context.Context, id int64) (*Area, error) {
	return scanArea(s.DB.QueryRowContext(ctx, `SELECT `+areaCols+` FROM areas WHERE id=?`, id))
}

func (s *Store) CreateArea(ctx context.Context, name, group string) (*Area, error) {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO areas(name, oidc_group, created_at) VALUES(?,?,?)`, name, nullStr(group), time.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.AreaByID(ctx, id)
}

func (s *Store) UpdateArea(ctx context.Context, id int64, name, group string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE areas SET name=?, oidc_group=? WHERE id=?`, name, nullStr(group), id)
	return err
}

func (s *Store) SetAreaRecipients(ctx context.Context, id int64, recipients []string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE areas SET recipients=? WHERE id=?`, strings.Join(recipients, ","), id)
	return err
}

// ErrAreaNotEmpty is returned when deleting an area that still has devices.
var ErrAreaNotEmpty = errors.New("the area still has devices")

// DeleteArea deletes an area without devices together with its enrollment
// tokens and memberships.
func (s *Store) DeleteArea(ctx context.Context, id int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE area_id=?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrAreaNotEmpty
	}
	for _, q := range []string{`DELETE FROM enrollment_tokens WHERE area_id=?`, `DELETE FROM user_areas WHERE area_id=?`, `DELETE FROM areas WHERE id=?`} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AreaDeviceCounts returns the number of devices per area.
func (s *Store) AreaDeviceCounts(ctx context.Context) (map[int64]int, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT area_id, COUNT(*) FROM devices GROUP BY area_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// Memberships returns all memberships (userID = 0) or those of one user.
func (s *Store) Memberships(ctx context.Context, userID int64) ([]Membership, error) {
	q, args := `SELECT user_id, area_id, source FROM user_areas`, []any{}
	if userID != 0 {
		q += ` WHERE user_id=?`
		args = append(args, userID)
	}
	rows, err := s.DB.QueryContext(ctx, q+` ORDER BY user_id, area_id, source`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.UserID, &m.AreaID, &m.Source); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UserAreaIDs returns the distinct areas a user is a member of.
func (s *Store) UserAreaIDs(ctx context.Context, userID int64) ([]int64, error) {
	ms, err := s.Memberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []int64
	for _, m := range ms {
		if !slices.Contains(out, m.AreaID) {
			out = append(out, m.AreaID)
		}
	}
	return out, nil
}

// SetMemberships replaces the memberships of one source for a user.
func (s *Store) SetMemberships(ctx context.Context, userID int64, source string, areas []int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_areas WHERE user_id=? AND source=?`, userID, source); err != nil {
		return err
	}
	for _, a := range areas {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO user_areas(user_id, area_id, source) SELECT ?, id, ? FROM areas WHERE id=?`, userID, source, a); err != nil {
			return err
		}
	}
	return tx.Commit()
}
