package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

type rawSection struct {
	CollectedAt time.Time       `json:"collected_at"`
	DurationMs  int64           `json:"duration_ms"`
	Error       string          `json:"error,omitempty"`
	Warnings    []string        `json:"warnings,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}

// ingest stores a report: latest snapshots plus derived history.
func (s *Server) ingest(ctx context.Context, d *store.Device, sections map[string]json.RawMessage) error {
	now := time.Now()
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for name, raw := range sections {
		if !slices.Contains(protocol.AllCollectors, name) {
			continue
		}
		var sec rawSection
		if err := json.Unmarshal(raw, &sec); err != nil {
			return fmt.Errorf("section %s: %w", name, err)
		}
		if sec.CollectedAt.IsZero() || sec.CollectedAt.After(now.Add(24*time.Hour)) {
			sec.CollectedAt = now
		}
		snap := store.Snapshot{DeviceID: d.ID, Collector: name, CollectedAt: sec.CollectedAt, ReceivedAt: now,
			DurationMs: sec.DurationMs, Error: truncate(sec.Error, 2000), Warnings: sec.Warnings}
		if sec.Error == "" && len(sec.Data) > 0 && string(sec.Data) != "null" {
			// Decode into the typed structure: validates and normalises the payload.
			norm, err := s.derive(ctx, tx, d, name, sec, now)
			if err != nil {
				return fmt.Errorf("section %s: %w", name, err)
			}
			snap.Data = norm
		}
		if err := s.store.PutSnapshot(ctx, tx, snap); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Server) derive(ctx context.Context, tx *sql.Tx, d *store.Device, name string, sec rawSection, now time.Time) (json.RawMessage, error) {
	switch name {
	case protocol.CollectSystem:
		var v protocol.SystemInfo
		if err := json.Unmarshal(sec.Data, &v); err != nil {
			return nil, err
		}
		if v.OS.Name != "" {
			if _, err := tx.ExecContext(ctx, `UPDATE devices SET os_name=? WHERE id=?`, v.OS.Name, d.ID); err != nil {
				return nil, err
			}
		}
		return json.Marshal(v)

	case protocol.CollectSMART:
		var v protocol.SmartData
		if err := json.Unmarshal(sec.Data, &v); err != nil {
			return nil, err
		}
		day := sec.CollectedAt.In(time.Local).Format("2006-01-02")
		for _, dk := range v.Disks {
			if dk.Serial == "" {
				continue
			}
			p := store.SmartPoint{Serial: dk.Serial, Day: day, Time: sec.CollectedAt, HealthPassed: dk.HealthPassed,
				PowerOnHours: dk.PowerOnHours, Reallocated: dk.Reallocated, Pending: dk.Pending, Uncorrectable: dk.Uncorrectable,
				CRCErrors: dk.CRCErrors, MediaErrors: dk.MediaErrors,
				Temperature: i64(dk.Temperature), PercentUsed: i64(dk.PercentUsed), AvailableSpare: i64(dk.AvailableSpare)}
			if err := s.store.PutSmartPoint(ctx, tx, d.ID, p); err != nil {
				return nil, err
			}
		}
		return json.Marshal(v)

	case protocol.CollectSoftware:
		var v protocol.SoftwareData
		if err := json.Unmarshal(sec.Data, &v); err != nil {
			return nil, err
		}
		if err := s.diffSoftware(ctx, tx, d.ID, v, sec.CollectedAt); err != nil {
			return nil, err
		}
		return json.Marshal(v)

	case protocol.CollectEvents:
		var v protocol.EventsData
		if err := json.Unmarshal(sec.Data, &v); err != nil {
			return nil, err
		}
		for _, e := range v.Events {
			if e.Key == "" {
				e.Key = fmt.Sprintf("%s|%d|%s", e.Kind, e.Time.Unix(), truncate(e.Message, 64))
			}
			if _, err := s.store.AddEvent(ctx, tx, store.Event{DeviceID: d.ID, Key: truncate(e.Key, 200), Kind: e.Kind, Time: e.Time,
				Source: e.Source, EventID: e.EventID, Disk: e.Device, External: e.External, Message: truncate(e.Message, 4000), ReceivedAt: now}); err != nil {
				return nil, err
			}
		}
		// The snapshot keeps only the scan window, events live in their own table.
		v.Events = nil
		return json.Marshal(v)

	case protocol.CollectUpdates:
		var v protocol.UpdatesData
		if err := json.Unmarshal(sec.Data, &v); err != nil {
			return nil, err
		}
		return json.Marshal(v)

	case protocol.CollectAutostart:
		var v protocol.AutostartData
		if err := json.Unmarshal(sec.Data, &v); err != nil {
			return nil, err
		}
		return json.Marshal(v)
	}
	return sec.Data, nil
}

func i64(p *int) *int64 {
	if p == nil {
		return nil
	}
	v := int64(*p)
	return &v
}

// diffSoftware records installed/removed/updated software compared to the previous snapshot.
func (s *Server) diffSoftware(ctx context.Context, tx *sql.Tx, deviceID string, cur protocol.SoftwareData, at time.Time) error {
	var prevRaw sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT data FROM snapshots WHERE device_id=? AND collector=?`, deviceID, protocol.CollectSoftware).Scan(&prevRaw)
	if err == sql.ErrNoRows || !prevRaw.Valid {
		return nil // first inventory: nothing to compare against
	}
	if err != nil {
		return err
	}
	var prev protocol.SoftwareData
	if err := json.Unmarshal([]byte(prevRaw.String), &prev); err != nil {
		return nil
	}
	old := map[string]protocol.SoftwareItem{}
	for _, it := range prev.Items {
		old[it.Key()] = it
	}
	seen := map[string]bool{}
	for _, it := range cur.Items {
		k := it.Key()
		seen[k] = true
		o, ok := old[k]
		switch {
		case !ok:
			if err := s.store.AddSoftwareChange(ctx, tx, store.SoftwareChange{DeviceID: deviceID, Time: at, Change: "installed", Name: it.Name, Source: it.Source, Scope: it.Scope, VersionNew: it.Version}); err != nil {
				return err
			}
		case o.Version != it.Version:
			if err := s.store.AddSoftwareChange(ctx, tx, store.SoftwareChange{DeviceID: deviceID, Time: at, Change: "updated", Name: it.Name, Source: it.Source, Scope: it.Scope, VersionOld: o.Version, VersionNew: it.Version}); err != nil {
				return err
			}
		}
	}
	for k, o := range old {
		if !seen[k] {
			if err := s.store.AddSoftwareChange(ctx, tx, store.SoftwareChange{DeviceID: deviceID, Time: at, Change: "removed", Name: o.Name, Source: o.Source, Scope: o.Scope, VersionOld: o.Version}); err != nil {
				return err
			}
		}
	}
	return nil
}
