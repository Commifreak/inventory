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
		if err := s.systemChanges(ctx, tx, d.ID, v, sec.CollectedAt, now); err != nil {
			return nil, err
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
		if err := s.autostartChanges(ctx, tx, d.ID, v, sec.CollectedAt, now); err != nil {
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
	for _, c := range softwareChanges(prev.Items, cur.Items) {
		c.DeviceID, c.Time = deviceID, at
		if err := s.store.AddSoftwareChange(ctx, tx, c); err != nil {
			return err
		}
	}
	return nil
}

// softwareChanges compares two inventories. Items are grouped by Key; a key
// can occur several times (e.g. a stale uninstall entry of an older version
// next to the current one), so the versions of a key are compared as a
// multiset: unchanged versions are ignored, the remaining old/new versions
// are paired as updates and any surplus counts as installed or removed.
func softwareChanges(prev, cur []protocol.SoftwareItem) []store.SoftwareChange {
	group := func(items []protocol.SoftwareItem) (map[string][]protocol.SoftwareItem, []string) {
		m := map[string][]protocol.SoftwareItem{}
		var order []string
		for _, it := range items {
			k := it.Key()
			if _, ok := m[k]; !ok {
				order = append(order, k)
			}
			m[k] = append(m[k], it)
		}
		return m, order
	}
	oldG, oldOrder := group(prev)
	newG, newOrder := group(cur)
	var out []store.SoftwareChange
	mk := func(change string, it protocol.SoftwareItem) store.SoftwareChange {
		return store.SoftwareChange{Change: change, Name: it.Name, Source: it.Source, Scope: it.Scope}
	}
	for _, k := range newOrder {
		olds := slices.Clone(oldG[k])
		var added []protocol.SoftwareItem
		for _, it := range newG[k] {
			if i := slices.IndexFunc(olds, func(o protocol.SoftwareItem) bool { return o.Version == it.Version }); i >= 0 {
				olds = slices.Delete(olds, i, i+1)
			} else {
				added = append(added, it)
			}
		}
		for i, it := range added {
			if i < len(olds) {
				c := mk("updated", it)
				c.VersionOld, c.VersionNew = olds[i].Version, it.Version
				out = append(out, c)
				continue
			}
			c := mk("installed", it)
			c.VersionNew = it.Version
			out = append(out, c)
		}
		for _, o := range olds[min(len(added), len(olds)):] {
			c := mk("removed", o)
			c.VersionOld = o.Version
			out = append(out, c)
		}
	}
	for _, k := range oldOrder {
		if _, ok := newG[k]; ok {
			continue
		}
		for _, o := range oldG[k] {
			c := mk("removed", o)
			c.VersionOld = o.Version
			out = append(out, c)
		}
	}
	return out
}
