package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

// Security change detection: items ever seen per device are remembered
// (seen_items); items that show up later become events, which the event
// based alert rules (admin_added, autostart_added, defender_exclusion_added)
// pick up. The first report only records the baseline.

func (s *Server) addChangeEvents(ctx context.Context, tx *sql.Tx, deviceID, seenKind, eventKind string, items []string, describe func(string) string, at, now time.Time) error {
	added, err := s.store.MarkSeen(ctx, tx, deviceID, seenKind, items, now)
	if err != nil {
		return err
	}
	for _, it := range added {
		sum := sha256.Sum256([]byte(it))
		if _, err := s.store.AddEvent(ctx, tx, store.Event{DeviceID: deviceID, Key: eventKind + "|" + hex.EncodeToString(sum[:16]), Kind: eventKind,
			Time: at, Source: "inventory", Message: truncate(describe(it), 4000), ReceivedAt: now}); err != nil {
			return err
		}
	}
	return nil
}

// systemChanges handles local administrators, Defender exclusions and
// Defender detections of a system report.
func (s *Server) systemChanges(ctx context.Context, tx *sql.Tx, deviceID string, v protocol.SystemInfo, at, now time.Time) error {
	// An empty list means the query failed - never a baseline.
	if len(v.Users.Admins) > 0 {
		if err := s.addChangeEvents(ctx, tx, deviceID, "admin", protocol.EventAdminAdded, v.Users.Admins,
			func(a string) string { return "New local administrator: " + a }, at, now); err != nil {
			return err
		}
	}
	df := v.Security.Defender
	if df == nil {
		return nil
	}
	if df.Exclusions != nil { // nil: not readable / old agent
		if err := s.addChangeEvents(ctx, tx, deviceID, "defender_exclusion", protocol.EventDefenderExclusion, df.Exclusions,
			func(e string) string { return "New Microsoft Defender exclusion: " + e }, at, now); err != nil {
			return err
		}
	}
	for _, det := range df.Detections {
		t := det.Time
		if t.IsZero() {
			t = at
		}
		msg := fmt.Sprintf("Microsoft Defender detected %s", det.Threat)
		if det.Severity != "" {
			msg += " (" + det.Severity + ")"
		}
		msg += " – " + det.Status
		if len(det.Resources) > 0 {
			msg += ": " + strings.Join(det.Resources, ", ")
		}
		if _, err := s.store.AddEvent(ctx, tx, store.Event{DeviceID: deviceID, Key: truncate("malware|"+det.ID, 200), Kind: protocol.EventMalware,
			Time: t, Source: "Microsoft Defender", Message: truncate(msg, 4000), ReceivedAt: now}); err != nil {
			return err
		}
	}
	return nil
}

// autostartChanges reports new autostart entries that are not part of
// Windows/the OS. RunOnce entries are transient (installers, updates) and
// ignored.
func (s *Server) autostartChanges(ctx context.Context, tx *sql.Tx, deviceID string, v protocol.AutostartData, at, now time.Time) error {
	var keys []string
	byKey := map[string]protocol.AutostartItem{}
	for _, it := range v.Items {
		if it.Vendor || strings.Contains(strings.ToLower(it.Location), "runonce") {
			continue
		}
		k := it.Location + "|" + it.Scope + "|" + it.Name
		keys = append(keys, k)
		byKey[k] = it
	}
	return s.addChangeEvents(ctx, tx, deviceID, "autostart", protocol.EventAutostartAdded, keys, func(k string) string {
		it := byKey[k]
		msg := fmt.Sprintf("New autostart entry: %s (%s", it.Name, it.Location)
		if it.Scope != "" && it.Scope != "machine" {
			msg += ", " + it.Scope
		}
		msg += ")"
		if it.Command != "" {
			msg += " – " + it.Command
		}
		return msg
	}, at, now)
}
