package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

func TestCRCErrorsIncreasing(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	er := enroll(t, ts, toks[0].Token, protocol.Identity{Hostname: "NUC", OS: "windows", Arch: "amd64", HardwareID: "HW"})
	report := func(crc int64, at time.Time) {
		rep := protocol.Report{AgentVersion: "0.0.9", Sections: map[string]protocol.Section{protocol.CollectSMART: {CollectedAt: at, Data: protocol.SmartData{Disks: []protocol.Disk{
			{Device: "Disk 0", Model: "SAMSUNG MZNTY128", Serial: "S2Y", Protocol: "ATA", System: true, HealthPassed: ptr(true), CRCErrors: ptr(crc)}}}}}}
		if code := postJSON(t, ts.URL+protocol.APIPrefix+"/report", er.Credential, rep, nil); code != 200 {
			t.Fatalf("report: %d", code)
		}
		s.runAlerts(ctx, nil)
	}
	open := func() string {
		alerts, _ := s.store.OpenAlertsForDevice(ctx, er.DeviceID)
		for _, a := range alerts {
			if a.Rule == "smart_crc" {
				return a.Message
			}
		}
		return ""
	}
	// An old count alone does not alert.
	report(328, time.Now().AddDate(0, 0, -2))
	if m := open(); m != "" {
		t.Fatalf("alert for old CRC errors: %s", m)
	}
	// The count grows: alert with the number of new errors.
	report(331, time.Now())
	if m := open(); !strings.Contains(m, "3 new interface CRC error(s)") {
		t.Fatalf("no alert for growing CRC errors: %q", m)
	}
}

func TestPowerLossIncreasing(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	er := enroll(t, ts, toks[0].Token, protocol.Identity{Hostname: "PC", OS: "windows", Arch: "amd64", HardwareID: "HW"})
	report := func(n int64, at time.Time) {
		rep := protocol.Report{AgentVersion: "0.0.9", Sections: map[string]protocol.Section{protocol.CollectSMART: {CollectedAt: at, Data: protocol.SmartData{Disks: []protocol.Disk{
			{Device: "/dev/nvme0", Serial: "N1", Protocol: "NVMe", System: true, HealthPassed: ptr(true), UnsafeShutdowns: ptr(n)}}}}}}
		postJSON(t, ts.URL+protocol.APIPrefix+"/report", er.Credential, rep, nil)
		s.runAlerts(ctx, nil)
	}
	msg := func() string {
		alerts, _ := s.store.OpenAlertsForDevice(ctx, er.DeviceID)
		for _, a := range alerts {
			if a.Rule == "power_loss" {
				return a.Message
			}
		}
		return ""
	}
	report(87, time.Now().AddDate(0, 0, -3))
	report(89, time.Now().AddDate(0, 0, -1)) // +2: below the default minimum of 3
	if m := msg(); m != "" {
		t.Fatalf("alert below the minimum: %s", m)
	}
	report(91, time.Now()) // +4 within 7 days
	if m := msg(); !strings.Contains(m, "4 unexpected power loss(es)") {
		t.Fatalf("no power loss alert: %q", m)
	}
}

func TestReallocatedNewOrFirst(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	er := enroll(t, ts, toks[0].Token, protocol.Identity{Hostname: "PC", OS: "windows", Arch: "amd64", HardwareID: "HW"})
	report := func(realloc, media int64, at time.Time) {
		rep := protocol.Report{AgentVersion: "0.0.9", Sections: map[string]protocol.Section{protocol.CollectSMART: {CollectedAt: at, Data: protocol.SmartData{Disks: []protocol.Disk{
			{Device: "/dev/sda", Serial: "HDD1", Protocol: "ATA", System: true, HealthPassed: ptr(true), Reallocated: ptr(realloc)},
			{Device: "/dev/nvme0", Serial: "NV1", Protocol: "NVMe", HealthPassed: ptr(true), MediaErrors: ptr(media)}}}}}}
		postJSON(t, ts.URL+protocol.APIPrefix+"/report", er.Credential, rep, nil)
		s.runAlerts(ctx, nil)
	}
	open := func(rule string) string {
		alerts, _ := s.store.OpenAlertsForDevice(ctx, er.DeviceID)
		for _, a := range alerts {
			if a.Rule == rule {
				return a.Message
			}
		}
		return ""
	}
	// First report with old damage: alert (disk first reported).
	report(3, 2, time.Now())
	if !strings.Contains(open("smart_reallocated"), "first reported") || !strings.Contains(open("nvme_media_errors"), "first reported") {
		t.Fatalf("no alert for a disk first reported with damage: %q / %q", open("smart_reallocated"), open("nvme_media_errors"))
	}
	// Ten days later, unchanged: resolved.
	old := time.Now().AddDate(0, 0, -10)
	if _, err := s.store.DB.Exec(`UPDATE smart_history SET ts=?, day=?`, old.Unix(), old.Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	report(3, 2, time.Now())
	if m := open("smart_reallocated") + open("nvme_media_errors"); m != "" {
		t.Fatalf("alert for an unchanged count: %s", m)
	}
	// Grown: alert again.
	report(5, 3, time.Now().Add(time.Minute))
	if !strings.Contains(open("smart_reallocated"), "2 new") || !strings.Contains(open("nvme_media_errors"), "1 new") {
		t.Fatalf("no alert for grown counts: %q / %q", open("smart_reallocated"), open("nvme_media_errors"))
	}
}

func TestDiskErrorCounters(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	er := enroll(t, ts, toks[0].Token, protocol.Identity{Hostname: "PC", OS: "linux", Arch: "amd64", HardwareID: "HW"})
	report := func(unc, timeout, spin int64, at time.Time) {
		rep := protocol.Report{AgentVersion: "0.0.9", Sections: map[string]protocol.Section{protocol.CollectSMART: {CollectedAt: at, Data: protocol.SmartData{Disks: []protocol.Disk{
			{Device: "/dev/sda", Serial: "HDD", Protocol: "ATA", System: true, HealthPassed: ptr(true), ReportedUncorrect: ptr(unc), CommandTimeout: ptr(timeout), SpinRetry: ptr(spin)}}}}}}
		postJSON(t, ts.URL+protocol.APIPrefix+"/report", er.Credential, rep, nil)
		s.runAlerts(ctx, nil)
	}
	open := func() string {
		alerts, _ := s.store.OpenAlertsForDevice(ctx, er.DeviceID)
		for _, a := range alerts {
			if a.Rule == "smart_error_counters" {
				return a.Message
			}
		}
		return ""
	}
	// First report: old command timeouts do not alert, spin retries do.
	report(0, 4295032833, 0, time.Now())
	if m := open(); m != "" {
		t.Fatalf("alert for old command timeouts: %s", m)
	}
	old := time.Now().AddDate(0, 0, -10)
	_, _ = s.store.DB.Exec(`UPDATE smart_history SET ts=?, day=?`, old.Unix(), old.Format("2006-01-02"))
	report(2, 4295032834, 0, time.Now())
	if m := open(); !strings.Contains(m, "2 new reported uncorrectable errors") || !strings.Contains(m, "command timeouts increased") {
		t.Fatalf("growth not reported: %q", m)
	}
}
