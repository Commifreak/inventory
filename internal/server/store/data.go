package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ---------------------------------------------------------------------------
// snapshots: latest output per collector
// ---------------------------------------------------------------------------

type Snapshot struct {
	DeviceID    string
	Collector   string
	CollectedAt time.Time
	ReceivedAt  time.Time
	DurationMs  int64
	Error       string
	Warnings    []string
	Data        json.RawMessage
}

func (s *Store) PutSnapshot(ctx context.Context, tx *sql.Tx, sn Snapshot) error {
	w, _ := json.Marshal(sn.Warnings)
	var data any
	if len(sn.Data) > 0 {
		data = string(sn.Data)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO snapshots(device_id, collector, collected_at, received_at, duration_ms, error, warnings, data) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(device_id, collector) DO UPDATE SET collected_at=excluded.collected_at, received_at=excluded.received_at, duration_ms=excluded.duration_ms,
 error=excluded.error, warnings=excluded.warnings, data=COALESCE(excluded.data, snapshots.data)`,
		sn.DeviceID, sn.Collector, sn.CollectedAt.Unix(), sn.ReceivedAt.Unix(), sn.DurationMs, nullStr(sn.Error), string(w), data)
	return err
}

func scanSnapshot(row interface{ Scan(...any) error }) (*Snapshot, error) {
	var sn Snapshot
	var c, r int64
	var dur sql.NullInt64
	var e, w, d sql.NullString
	if err := row.Scan(&sn.DeviceID, &sn.Collector, &c, &r, &dur, &e, &w, &d); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	sn.CollectedAt, sn.ReceivedAt, sn.DurationMs, sn.Error = time.Unix(c, 0), time.Unix(r, 0), dur.Int64, e.String
	if w.Valid {
		_ = json.Unmarshal([]byte(w.String), &sn.Warnings)
	}
	if d.Valid {
		sn.Data = json.RawMessage(d.String)
	}
	return &sn, nil
}

const snapCols = `device_id, collector, collected_at, received_at, duration_ms, error, warnings, data`

func (s *Store) GetSnapshot(ctx context.Context, deviceID, collector string) (*Snapshot, error) {
	return scanSnapshot(s.DB.QueryRowContext(ctx, `SELECT `+snapCols+` FROM snapshots WHERE device_id=? AND collector=?`, deviceID, collector))
}

// Snapshots returns all snapshots of a device keyed by collector.
func (s *Store) Snapshots(ctx context.Context, deviceID string) (map[string]*Snapshot, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+snapCols+` FROM snapshots WHERE device_id=?`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*Snapshot{}
	for rows.Next() {
		sn, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out[sn.Collector] = sn
	}
	return out, rows.Err()
}

// AllSnapshots returns snapshots of the given collectors for all devices: device -> collector -> snapshot.
func (s *Store) AllSnapshots(ctx context.Context, collectors ...string) (map[string]map[string]*Snapshot, error) {
	q := `SELECT ` + snapCols + ` FROM snapshots`
	var args []any
	if len(collectors) > 0 {
		q += ` WHERE collector IN (?` + repeat(",?", len(collectors)-1) + `)`
		for _, c := range collectors {
			args = append(args, c)
		}
	}
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]*Snapshot{}
	for rows.Next() {
		sn, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		if out[sn.DeviceID] == nil {
			out[sn.DeviceID] = map[string]*Snapshot{}
		}
		out[sn.DeviceID][sn.Collector] = sn
	}
	return out, rows.Err()
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

// ---------------------------------------------------------------------------
// SMART history (one row per disk and day)
// ---------------------------------------------------------------------------

type SmartPoint struct {
	Serial         string
	Day            string
	Time           time.Time
	HealthPassed   *bool
	Temperature    *int64
	PowerOnHours   *int64
	Reallocated    *int64
	Pending        *int64
	Uncorrectable  *int64
	CRCErrors      *int64
	PercentUsed    *int64
	AvailableSpare *int64
	MediaErrors    *int64
}

func (s *Store) PutSmartPoint(ctx context.Context, tx *sql.Tx, deviceID string, p SmartPoint) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO smart_history(device_id, serial, day, ts, health_passed, temperature, power_on_hours, reallocated, pending, uncorrectable, crc_errors, percent_used, available_spare, media_errors)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id, serial, day) DO UPDATE SET ts=excluded.ts, health_passed=excluded.health_passed, temperature=excluded.temperature,
 power_on_hours=excluded.power_on_hours, reallocated=excluded.reallocated, pending=excluded.pending, uncorrectable=excluded.uncorrectable, crc_errors=excluded.crc_errors,
 percent_used=excluded.percent_used, available_spare=excluded.available_spare, media_errors=excluded.media_errors`,
		deviceID, p.Serial, p.Day, p.Time.Unix(), p.HealthPassed, p.Temperature, p.PowerOnHours, p.Reallocated, p.Pending, p.Uncorrectable, p.CRCErrors, p.PercentUsed, p.AvailableSpare, p.MediaErrors)
	return err
}

func (s *Store) SmartHistory(ctx context.Context, deviceID, serial string, since time.Time) ([]SmartPoint, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT serial, day, ts, health_passed, temperature, power_on_hours, reallocated, pending, uncorrectable, crc_errors, percent_used, available_spare, media_errors
FROM smart_history WHERE device_id=? AND serial=? AND ts>=? ORDER BY day`, deviceID, serial, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SmartPoint
	for rows.Next() {
		var p SmartPoint
		var ts int64
		var hp sql.NullBool
		var vals [9]sql.NullInt64
		if err := rows.Scan(&p.Serial, &p.Day, &ts, &hp, &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5], &vals[6], &vals[7], &vals[8]); err != nil {
			return nil, err
		}
		p.Time = time.Unix(ts, 0)
		if hp.Valid {
			b := hp.Bool
			p.HealthPassed = &b
		}
		ptr := func(n sql.NullInt64) *int64 {
			if !n.Valid {
				return nil
			}
			v := n.Int64
			return &v
		}
		p.Temperature, p.PowerOnHours, p.Reallocated, p.Pending, p.Uncorrectable = ptr(vals[0]), ptr(vals[1]), ptr(vals[2]), ptr(vals[3]), ptr(vals[4])
		p.CRCErrors, p.PercentUsed, p.AvailableSpare, p.MediaErrors = ptr(vals[5]), ptr(vals[6]), ptr(vals[7]), ptr(vals[8])
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// software change log
// ---------------------------------------------------------------------------

type SoftwareChange struct {
	ID         int64
	DeviceID   string
	Time       time.Time
	Change     string // installed, removed, updated
	Name       string
	Source     string
	Scope      string
	VersionOld string
	VersionNew string
}

func (s *Store) AddSoftwareChange(ctx context.Context, tx *sql.Tx, c SoftwareChange) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO software_changes(device_id, ts, change, name, source, scope, version_old, version_new) VALUES(?,?,?,?,?,?,?,?)`,
		c.DeviceID, c.Time.Unix(), c.Change, c.Name, nullStr(c.Source), nullStr(c.Scope), nullStr(c.VersionOld), nullStr(c.VersionNew))
	return err
}

func (s *Store) SoftwareChanges(ctx context.Context, deviceID string, limit int) ([]SoftwareChange, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, device_id, ts, change, name, COALESCE(source,''), COALESCE(scope,''), COALESCE(version_old,''), COALESCE(version_new,'')
FROM software_changes WHERE device_id=? ORDER BY ts DESC, id DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SoftwareChange
	for rows.Next() {
		var c SoftwareChange
		var ts int64
		if err := rows.Scan(&c.ID, &c.DeviceID, &ts, &c.Change, &c.Name, &c.Source, &c.Scope, &c.VersionOld, &c.VersionNew); err != nil {
			return nil, err
		}
		c.Time = time.Unix(ts, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// critical events
// ---------------------------------------------------------------------------

type Event struct {
	DeviceID   string
	Key        string
	Kind       string
	Time       time.Time
	Source     string
	EventID    int
	Disk       string
	Message    string
	ReceivedAt time.Time
}

// AddEvent inserts an event; returns true if it was new.
func (s *Store) AddEvent(ctx context.Context, tx *sql.Tx, e Event) (bool, error) {
	res, err := tx.ExecContext(ctx, `INSERT INTO events(device_id, key, kind, ts, source, event_id, disk, message, received_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`,
		e.DeviceID, e.Key, e.Kind, e.Time.Unix(), nullStr(e.Source), e.EventID, nullStr(e.Disk), e.Message, e.ReceivedAt.Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) Events(ctx context.Context, deviceID string, since time.Time, limit int) ([]Event, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT device_id, key, kind, ts, COALESCE(source,''), COALESCE(event_id,0), COALESCE(disk,''), COALESCE(message,''), received_at
FROM events WHERE device_id=? AND ts>=? ORDER BY ts DESC LIMIT ?`, deviceID, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts, rec int64
		if err := rows.Scan(&e.DeviceID, &e.Key, &e.Kind, &ts, &e.Source, &e.EventID, &e.Disk, &e.Message, &rec); err != nil {
			return nil, err
		}
		e.Time, e.ReceivedAt = time.Unix(ts, 0), time.Unix(rec, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountEvents counts events of a kind since t, per device.
func (s *Store) CountEvents(ctx context.Context, deviceID, kind string, since time.Time) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE device_id=? AND kind=? AND ts>=?`, deviceID, kind, since.Unix()).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------------------
// retention
// ---------------------------------------------------------------------------

// Prune deletes history older than the cutoff.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) error {
	c := cutoff.Unix()
	for _, q := range []string{
		`DELETE FROM smart_history WHERE ts<?`,
		`DELETE FROM software_changes WHERE ts<?`,
		`DELETE FROM events WHERE ts<?`,
		`DELETE FROM alerts WHERE state='resolved' AND resolved_at<?`,
		`DELETE FROM agent_update_log WHERE ts<?`,
		`DELETE FROM audit_log WHERE ts<?`,
	} {
		if _, err := s.DB.ExecContext(ctx, q, c); err != nil {
			return err
		}
	}
	return nil
}
