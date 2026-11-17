package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// enrollment tokens
// ---------------------------------------------------------------------------

type EnrollmentToken struct {
	ID         int64
	Token      string
	Name       string
	CreatedAt  time.Time
	RevokedAt  time.Time
	LastUsedAt time.Time
	UseCount   int
}

func (t EnrollmentToken) Active() bool { return t.RevokedAt.IsZero() }

func scanToken(row interface{ Scan(...any) error }) (*EnrollmentToken, error) {
	var t EnrollmentToken
	var c int64
	var r, l sql.NullInt64
	if err := row.Scan(&t.ID, &t.Token, &t.Name, &c, &r, &l, &t.UseCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.CreatedAt, t.RevokedAt, t.LastUsedAt = time.Unix(c, 0), tu(r), tu(l)
	return &t, nil
}

const tokenCols = `id, token, name, created_at, revoked_at, last_used_at, use_count`

func (s *Store) CreateToken(ctx context.Context, token, name string) (*EnrollmentToken, error) {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO enrollment_tokens(token, name, created_at) VALUES(?,?,?)`, token, name, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.TokenByID(ctx, id)
}

func (s *Store) TokenByID(ctx context.Context, id int64) (*EnrollmentToken, error) {
	return scanToken(s.DB.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens WHERE id=?`, id))
}

func (s *Store) TokenByValue(ctx context.Context, token string) (*EnrollmentToken, error) {
	return scanToken(s.DB.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens WHERE token=?`, token))
}

func (s *Store) ListTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens ORDER BY revoked_at IS NOT NULL, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *Store) RevokeToken(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE enrollment_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, time.Now().Unix(), id)
	return err
}

func (s *Store) UseToken(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE enrollment_tokens SET last_used_at=?, use_count=use_count+1 WHERE id=?`, time.Now().Unix(), id)
	return err
}

// ---------------------------------------------------------------------------
// devices
// ---------------------------------------------------------------------------

type Device struct {
	ID                string
	Hostname          string
	DisplayName       string
	OS                string
	Arch              string
	HardwareID        string
	MachineID         string
	CredentialHash    string
	EnrollmentTokenID int64
	EnrolledAt        time.Time
	LastSeenAt        time.Time
	LastIP            string
	AgentVersion      string
	BootTime          time.Time
	ClockSkewSec      int64
	OSName            string
	Ring              string
	PinnedVersion     string
	UpdateNowVersion  string
	UpdateTarget      string
	UpdateState       string
	UpdateError       string
	UpdateChangedAt   time.Time
	CollectNow        string
	OfflineAlertHours sql.NullInt64
	AlertsMuted       bool
	Notes             string
	RevokedAt         time.Time
}

// Name returns the display name or the hostname.
func (d Device) Name() string {
	if d.DisplayName != "" {
		return d.DisplayName
	}
	return d.Hostname
}

const deviceCols = `id, hostname, display_name, os, arch, hardware_id, machine_id, credential_hash, enrollment_token_id,
 enrolled_at, last_seen_at, last_ip, agent_version, boot_time, clock_skew_sec, os_name, ring, pinned_version,
 update_now_version, update_target, update_state, update_error, update_changed_at, collect_now, offline_alert_hours,
 alerts_muted, notes, revoked_at`

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	var dn, hw, mid, ip, av, osn, pin, unow, utarget, ust, uerr, cnow, notes sql.NullString
	var tok, last, boot, skew, uchg, rev sql.NullInt64
	var enrolled int64
	err := row.Scan(&d.ID, &d.Hostname, &dn, &d.OS, &d.Arch, &hw, &mid, &d.CredentialHash, &tok,
		&enrolled, &last, &ip, &av, &boot, &skew, &osn, &d.Ring, &pin,
		&unow, &utarget, &ust, &uerr, &uchg, &cnow, &d.OfflineAlertHours,
		&d.AlertsMuted, &notes, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.DisplayName, d.HardwareID, d.MachineID, d.LastIP, d.AgentVersion = dn.String, hw.String, mid.String, ip.String, av.String
	d.OSName, d.PinnedVersion, d.UpdateNowVersion, d.UpdateTarget = osn.String, pin.String, unow.String, utarget.String
	d.UpdateState, d.UpdateError, d.CollectNow, d.Notes = ust.String, uerr.String, cnow.String, notes.String
	d.EnrollmentTokenID = tok.Int64
	d.EnrolledAt = time.Unix(enrolled, 0)
	d.LastSeenAt, d.BootTime, d.UpdateChangedAt, d.RevokedAt = tu(last), tu(boot), tu(uchg), tu(rev)
	d.ClockSkewSec = skew.Int64
	return &d, nil
}

func (s *Store) DeviceByID(ctx context.Context, id string) (*Device, error) {
	return scanDevice(s.DB.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id=?`, id))
}

// FindDeviceByIdentity finds a non-revoked device by hardware or machine id.
// Both must match if both are known on either side.
func (s *Store) FindDeviceByIdentity(ctx context.Context, hardwareID, machineID string) (*Device, error) {
	if hardwareID == "" && machineID == "" {
		return nil, ErrNotFound
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE (hardware_id=? AND ?<>'') OR (machine_id=? AND ?<>'') ORDER BY enrolled_at DESC`,
		hardwareID, hardwareID, machineID, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var best *Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		hwMatch := hardwareID != "" && strings.EqualFold(d.HardwareID, hardwareID)
		midMatch := machineID != "" && strings.EqualFold(d.MachineID, machineID)
		// Cloned VMs share the hardware UUID only rarely, cloned disks share the machine id:
		// require hardware match, and machine match if both sides know it, or
		// fall back to machine match when no hardware id is available.
		ok := false
		switch {
		case hwMatch && (machineID == "" || d.MachineID == "" || midMatch):
			ok = true
		case hardwareID == "" && midMatch:
			ok = true
		case d.HardwareID == "" && midMatch:
			ok = true
		}
		if ok && best == nil {
			best = d
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	return best, rows.Err()
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY lower(COALESCE(display_name, hostname))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (s *Store) CreateDevice(ctx context.Context, d *Device) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO devices(id, hostname, os, arch, hardware_id, machine_id, credential_hash, enrollment_token_id, enrolled_at, agent_version, ring)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, d.ID, d.Hostname, d.OS, d.Arch, nullStr(d.HardwareID), nullStr(d.MachineID), d.CredentialHash,
		d.EnrollmentTokenID, d.EnrolledAt.Unix(), nullStr(d.AgentVersion), d.Ring)
	return err
}

// ReEnrollDevice gives an existing device a new credential (reinstall).
func (s *Store) ReEnrollDevice(ctx context.Context, id, credHash, hostname, osName, arch, agentVersion string, tokenID int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET credential_hash=?, hostname=?, os=?, arch=?, agent_version=?, enrollment_token_id=?, revoked_at=NULL,
 update_state=NULL, update_error=NULL, update_target=NULL, update_now_version=NULL WHERE id=?`,
		credHash, hostname, osName, arch, nullStr(agentVersion), tokenID, id)
	return err
}

// Checkin stores heartbeat data.
func (s *Store) Checkin(ctx context.Context, id string, at time.Time, ip, hostname, agentVersion, hardwareID, machineID string, boot time.Time, skew int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET last_seen_at=?, last_ip=?, hostname=?, agent_version=?, boot_time=?, clock_skew_sec=?,
 hardware_id=COALESCE(NULLIF(?,''), hardware_id), machine_id=COALESCE(NULLIF(?,''), machine_id) WHERE id=?`,
		at.Unix(), ip, hostname, nullStr(agentVersion), ut(boot), skew, hardwareID, machineID, id)
	return err
}

func (s *Store) SetDeviceOSName(ctx context.Context, id, name string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET os_name=? WHERE id=?`, nullStr(name), id)
	return err
}

// DeviceSettings are the user editable fields of a device.
type DeviceSettings struct {
	DisplayName       string
	Notes             string
	Ring              string
	PinnedVersion     string
	OfflineAlertHours sql.NullInt64
	AlertsMuted       bool
}

func (s *Store) UpdateDeviceSettings(ctx context.Context, id string, ds DeviceSettings) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET display_name=?, notes=?, ring=?, pinned_version=?, offline_alert_hours=?, alerts_muted=? WHERE id=?`,
		nullStr(ds.DisplayName), nullStr(ds.Notes), ds.Ring, nullStr(ds.PinnedVersion), ds.OfflineAlertHours, ds.AlertsMuted, id)
	return err
}

func (s *Store) SetDeviceRing(ctx context.Context, id, ring string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET ring=? WHERE id=?`, ring, id)
	return err
}

func (s *Store) SetUpdateNow(ctx context.Context, id, version string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET update_now_version=? WHERE id=?`, nullStr(version), id)
	return err
}

// SetUpdateState records the update state machine of a device.
func (s *Store) SetUpdateState(ctx context.Context, id, target, state, errMsg string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET update_target=?, update_state=?, update_error=?, update_changed_at=? WHERE id=?`,
		nullStr(target), nullStr(state), nullStr(errMsg), time.Now().Unix(), id)
	return err
}

func (s *Store) SetCollectNow(ctx context.Context, id, collectors string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET collect_now=? WHERE id=?`, nullStr(collectors), id)
	return err
}

func (s *Store) RevokeDevice(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE devices SET revoked_at=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM devices WHERE id=?`, id)
	return err
}

func (s *Store) LogAgentUpdate(ctx context.Context, deviceID, from, to string, success bool, errMsg string, at time.Time) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO agent_update_log(device_id, ts, from_version, to_version, success, error) VALUES(?,?,?,?,?,?)`,
		deviceID, at.Unix(), from, to, success, nullStr(errMsg))
	return err
}

type AgentUpdateLog struct {
	Time    time.Time
	From    string
	To      string
	Success bool
	Error   string
}

func (s *Store) ListAgentUpdates(ctx context.Context, deviceID string, limit int) ([]AgentUpdateLog, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT ts, COALESCE(from_version,''), COALESCE(to_version,''), success, COALESCE(error,'') FROM agent_update_log WHERE device_id=? ORDER BY ts DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentUpdateLog
	for rows.Next() {
		var l AgentUpdateLog
		var ts int64
		if err := rows.Scan(&ts, &l.From, &l.To, &l.Success, &l.Error); err != nil {
			return nil, err
		}
		l.Time = time.Unix(ts, 0)
		out = append(out, l)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// device flags ("condition holds since")
// ---------------------------------------------------------------------------

// SetFlag records that flag holds; returns the time since it holds.
func (s *Store) SetFlag(ctx context.Context, deviceID, flag string, on bool, now time.Time) (time.Time, error) {
	if !on {
		_, err := s.DB.ExecContext(ctx, `DELETE FROM device_flags WHERE device_id=? AND flag=?`, deviceID, flag)
		return time.Time{}, err
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO device_flags(device_id, flag, since) VALUES(?,?,?) ON CONFLICT DO NOTHING`, deviceID, flag, now.Unix()); err != nil {
		return time.Time{}, err
	}
	return s.FlagSince(ctx, deviceID, flag)
}

func (s *Store) FlagSince(ctx context.Context, deviceID, flag string) (time.Time, error) {
	var since int64
	err := s.DB.QueryRowContext(ctx, `SELECT since FROM device_flags WHERE device_id=? AND flag=?`, deviceID, flag).Scan(&since)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(since, 0), nil
}
