package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Alert states.
const (
	AlertOpen     = "open"
	AlertResolved = "resolved"
)

type Alert struct {
	ID             int64
	DeviceID       string
	Rule           string
	Subject        string
	Severity       string
	State          string
	Message        string
	OpenedAt       time.Time
	LastSeenAt     time.Time
	ResolvedAt     time.Time
	LastNotifiedAt time.Time
	NotifyCount    int
	NotifiedValue  *float64 // value at the last notification (step-notified rules)
}

const alertCols = `id, COALESCE(device_id,''), rule, subject, severity, state, message, opened_at, last_seen_at, resolved_at, last_notified_at, notify_count, notified_value`

func scanAlert(row interface{ Scan(...any) error }) (*Alert, error) {
	var a Alert
	var o, l int64
	var r, n sql.NullInt64
	var v sql.NullFloat64
	if err := row.Scan(&a.ID, &a.DeviceID, &a.Rule, &a.Subject, &a.Severity, &a.State, &a.Message, &o, &l, &r, &n, &a.NotifyCount, &v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.OpenedAt, a.LastSeenAt, a.ResolvedAt, a.LastNotifiedAt = time.Unix(o, 0), time.Unix(l, 0), tu(r), tu(n)
	if v.Valid {
		a.NotifiedValue = &v.Float64
	}
	return &a, nil
}

func (s *Store) queryAlerts(ctx context.Context, q string, args ...any) ([]Alert, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+alertCols+` FROM alerts `+q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// OpenAlerts returns all open alerts.
func (s *Store) OpenAlerts(ctx context.Context) ([]Alert, error) {
	return s.queryAlerts(ctx, `WHERE state='open' ORDER BY opened_at DESC`)
}

// DeviceAlerts returns open and recent alerts of a device.
func (s *Store) DeviceAlerts(ctx context.Context, deviceID string, limit int) ([]Alert, error) {
	return s.queryAlerts(ctx, `WHERE device_id=? ORDER BY state='open' DESC, opened_at DESC LIMIT ?`, deviceID, limit)
}

// RecentAlerts returns open and resolved alerts.
func (s *Store) RecentAlerts(ctx context.Context, limit int) ([]Alert, error) {
	return s.queryAlerts(ctx, `ORDER BY state='open' DESC, COALESCE(resolved_at, opened_at) DESC LIMIT ?`, limit)
}

func (s *Store) AlertByID(ctx context.Context, id int64) (*Alert, error) {
	return scanAlert(s.DB.QueryRowContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE id=?`, id))
}

// OpenAlert returns the open alert for (device, rule, subject).
func (s *Store) OpenAlert(ctx context.Context, deviceID, rule, subject string) (*Alert, error) {
	return scanAlert(s.DB.QueryRowContext(ctx, `SELECT `+alertCols+` FROM alerts WHERE device_id IS ? AND rule=? AND subject=? AND state='open'`, nullStr(deviceID), rule, subject))
}

// OpenAlertsForDevice returns open alerts of one device.
func (s *Store) OpenAlertsForDevice(ctx context.Context, deviceID string) ([]Alert, error) {
	return s.queryAlerts(ctx, `WHERE device_id=? AND state='open'`, deviceID)
}

func (s *Store) InsertAlert(ctx context.Context, a *Alert) error {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO alerts(device_id, rule, subject, severity, state, message, opened_at, last_seen_at) VALUES(?,?,?,?,?,?,?,?)`,
		nullStr(a.DeviceID), a.Rule, a.Subject, a.Severity, AlertOpen, a.Message, a.OpenedAt.Unix(), a.LastSeenAt.Unix())
	if err != nil {
		return err
	}
	a.ID, _ = res.LastInsertId()
	a.State = AlertOpen
	return nil
}

func (s *Store) TouchAlert(ctx context.Context, id int64, severity, message string, at time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE alerts SET severity=?, message=?, last_seen_at=? WHERE id=?`, severity, message, at.Unix(), id)
	return err
}

func (s *Store) ResolveAlert(ctx context.Context, id int64, at time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE alerts SET state='resolved', resolved_at=? WHERE id=?`, at.Unix(), id)
	return err
}

func (s *Store) MarkAlertNotified(ctx context.Context, id int64, at time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE alerts SET last_notified_at=?, notify_count=notify_count+1 WHERE id=?`, at.Unix(), id)
	return err
}

// SetAlertNotifiedValue records the value an alert was last notified with.
func (s *Store) SetAlertNotifiedValue(ctx context.Context, id int64, v float64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE alerts SET notified_value=? WHERE id=?`, v, id)
	return err
}
