package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

func TestSecurityChangesAndRules(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	api := ts.URL + protocol.APIPrefix
	var er protocol.EnrollResponse
	postJSON(t, api+"/enroll", "", protocol.EnrollRequest{Token: toks[0].Token, Identity: protocol.Identity{Hostname: "PC-SEC", OS: "windows", Arch: "amd64"}}, &er)
	now := time.Now()

	report := func(at time.Time, admins, exclusions []string, autostart []protocol.AutostartItem, fwPublic bool, dets []protocol.ThreatDetection) {
		t.Helper()
		sys := protocol.SystemInfo{
			OS:    protocol.OSInfo{Family: "windows", Name: "Windows 11 Pro"},
			Users: protocol.UsersInfo{Admins: admins},
			Security: protocol.SecurityInfo{
				Defender:  &protocol.DefenderInfo{Present: true, ServiceEnabled: true, AntivirusEnabled: true, RealTimeProtection: true, RunningMode: "Normal", Exclusions: exclusions, Detections: dets},
				Antivirus: []protocol.AntivirusProduct{{Name: "Microsoft Defender Antivirus", Enabled: true, UpToDate: true, Defender: true}, {Name: "OldScanner", Enabled: false}},
				Firewall:  []protocol.FirewallProfile{{Name: "Domain", Enabled: true}, {Name: "Private", Enabled: true}, {Name: "Public", Enabled: fwPublic, Active: true}},
			},
		}
		rep := protocol.Report{AgentVersion: "0.1.0", Sections: map[string]protocol.Section{
			protocol.CollectSystem:    {CollectedAt: at, Data: sys},
			protocol.CollectAutostart: {CollectedAt: at, Data: protocol.AutostartData{Items: autostart}},
		}}
		if code := postJSON(t, api+"/report", er.Credential, rep, nil); code != 200 {
			t.Fatalf("report: %d", code)
		}
	}
	vendor := protocol.AutostartItem{Name: "SecurityHealth", Location: `HKLM\Run`, Scope: "machine", Vendor: true}
	onedrive := protocol.AutostartItem{Name: "OneDrive", Location: `HKCU\Run`, Scope: `user:PC\anna`, Command: "onedrive.exe"}
	removed := protocol.ThreatDetection{ID: "{1}", Time: now.Add(-48 * time.Hour), Threat: "Trojan:Win32/Old", Severity: "severe", Status: "quarantined", Resolved: true, Resources: []string{`file:_C:\x.exe`}}

	// First report: baseline only, but Defender detections always count.
	report(now, []string{`PC\Administrator`, `PC\anna`}, []string{}, []protocol.AutostartItem{vendor, onedrive}, false, []protocol.ThreatDetection{removed})
	events, _ := s.store.Events(ctx, er.DeviceID, now.Add(-30*24*time.Hour), 100)
	kinds := map[string]int{}
	for _, e := range events {
		kinds[e.Kind]++
	}
	if kinds[protocol.EventAdminAdded]+kinds[protocol.EventAutostartAdded]+kinds[protocol.EventDefenderExclusion] != 0 || kinds[protocol.EventMalware] != 1 {
		t.Fatalf("baseline created change events: %v", kinds)
	}

	// Second report: new admin, new exclusion, new (non-vendor) autostart,
	// a RunOnce entry (ignored) and an allowed (unresolved) threat.
	evil := protocol.AutostartItem{Name: "Updater", Location: `HKLM\Run`, Scope: "machine", Command: `C:\Users\Public\upd.exe`}
	runonce := protocol.AutostartItem{Name: "cleanup", Location: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, Scope: "machine"}
	allowed := protocol.ThreatDetection{ID: "{2}", Time: now.Add(-time.Hour), Threat: "HackTool:Win32/Mimikatz", Status: "allowed", Resources: []string{`file:_C:\tools\m.exe`}}
	later := now.Add(time.Hour)
	report(later, []string{`PC\Administrator`, `PC\anna`, `PC\backdoor`}, []string{`path:C:\Users\Public`}, []protocol.AutostartItem{vendor, evil, runonce}, false, []protocol.ThreatDetection{allowed, removed})
	// OneDrive vanished (user logged off) and comes back: not new.
	report(later.Add(time.Minute), []string{`PC\Administrator`, `PC\anna`, `PC\backdoor`}, []string{`path:C:\Users\Public`}, []protocol.AutostartItem{vendor, evil, runonce, onedrive}, false, []protocol.ThreatDetection{allowed, removed})

	events, _ = s.store.Events(ctx, er.DeviceID, now.Add(-30*24*time.Hour), 100)
	kinds = map[string]int{}
	var msgs []string
	for _, e := range events {
		kinds[e.Kind]++
		msgs = append(msgs, e.Message)
	}
	if kinds[protocol.EventAdminAdded] != 1 || kinds[protocol.EventAutostartAdded] != 1 || kinds[protocol.EventDefenderExclusion] != 1 || kinds[protocol.EventMalware] != 2 {
		t.Fatalf("change events: %v %v", kinds, msgs)
	}
	all := strings.Join(msgs, "\n")
	for _, want := range []string{`New local administrator: PC\backdoor`, `New Microsoft Defender exclusion: path:C:\Users\Public`, `New autostart entry: Updater (HKLM\Run) – C:\Users\Public\upd.exe`, "HackTool:Win32/Mimikatz – allowed"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing event %q in:\n%s", want, all)
		}
	}

	s.runAlerts(ctx, nil)
	open, _ := s.store.OpenAlerts(ctx)
	rules := map[string]string{}
	for _, a := range open {
		if a.DeviceID == er.DeviceID {
			rules[a.Rule] = a.Message
		}
	}
	for _, want := range []string{"firewall_off", "malware_active", "malware_detected", "admin_added", "autostart_added", "defender_exclusion_added"} {
		if _, ok := rules[want]; !ok {
			t.Errorf("expected alert %s, open: %v", want, rules)
		}
	}
	if _, ok := rules["av_off"]; ok {
		t.Errorf("av_off raised although Defender is active")
	}
	if !strings.Contains(rules["malware_active"], "Mimikatz") || strings.Contains(rules["malware_active"], "Trojan:Win32/Old") {
		t.Errorf("malware_active must list only unresolved threats: %s", rules["malware_active"])
	}
	if !strings.Contains(rules["admin_added"], `PC\backdoor`) || !strings.Contains(rules["firewall_off"], "Public") {
		t.Errorf("alert messages: %v", rules)
	}

	// Firewall intentionally off on this device: disabling the rule resolves the alert.
	if err := s.store.SetDisabledRules(ctx, er.DeviceID, []string{"firewall_off"}); err != nil {
		t.Fatal(err)
	}
	s.runAlerts(ctx, nil)
	open, _ = s.store.OpenAlerts(ctx)
	for _, a := range open {
		if a.DeviceID == er.DeviceID && a.Rule == "firewall_off" {
			t.Errorf("firewall_off still open after disabling it for the device")
		}
	}
	if d, _ := s.store.DeviceByID(ctx, er.DeviceID); len(d.DisabledRules) != 1 || d.DisabledRules[0] != "firewall_off" {
		t.Errorf("disabled rules not stored: %+v", d.DisabledRules)
	}
}

func TestManagedAgentGetsNoUpdates(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	api := ts.URL + protocol.APIPrefix
	var er protocol.EnrollResponse
	postJSON(t, api+"/enroll", "", protocol.EnrollRequest{Token: toks[0].Token, Identity: protocol.Identity{Hostname: "homeassistant", OS: "linux", Arch: "arm64"}}, &er)
	var cr protocol.CheckinResponse
	if code := postJSON(t, api+"/checkin", er.Credential, protocol.CheckinRequest{AgentVersion: "0.0.1", Managed: "home-assistant"}, &cr); code != 200 {
		t.Fatalf("checkin: %d", code)
	}
	d, _ := s.store.DeviceByID(ctx, er.DeviceID)
	if d.Managed != "home-assistant" || cr.Update != nil {
		t.Fatalf("managed=%q update=%+v", d.Managed, cr.Update)
	}
	d.UpdateNowVersion = "9.9.9"
	if target, reason := TargetVersion(d, UpdatePolicy{}, s.agents); target != "" || !strings.Contains(reason, "Home Assistant") {
		t.Fatalf("managed device targeted: %q (%s)", target, reason)
	}
	// Back to a normal agent: the flag is cleared.
	postJSON(t, api+"/checkin", er.Credential, protocol.CheckinRequest{AgentVersion: "0.0.1"}, &cr)
	if d, _ := s.store.DeviceByID(ctx, er.DeviceID); d.Managed != "" {
		t.Fatalf("managed flag not cleared: %q", d.Managed)
	}
}
