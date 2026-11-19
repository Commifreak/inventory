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
