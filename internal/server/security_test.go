package server

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
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
	// The add-on update reported by the Supervisor marks the agent as outdated.
	rep := protocol.Report{AgentVersion: "0.0.1", Sections: map[string]protocol.Section{protocol.CollectUpdates: {CollectedAt: time.Now(), Data: protocol.UpdatesData{
		Manager: "Home Assistant Supervisor", PendingCount: 2, Pending: []protocol.PendingUpdate{
			{Title: "Add-on Mosquitto broker 6.5.1 → 6.5.2", Version: "6.5.2", Category: "Add-ons"},
			{Title: "Add-on Inventory Agent 0.0.1 → 0.2.0", Version: "0.2.0", Category: "Add-ons"}}}}}}
	postJSON(t, api+"/report", er.Credential, rep, nil)
	snaps, _ := s.store.Snapshots(ctx, er.DeviceID)
	d, _ = s.store.DeviceByID(ctx, er.DeviceID)
	if row := s.deviceRow(*d, snaps, nil, time.Now(), 300); row.AgentLatest != "0.2.0" {
		t.Fatalf("add-on update not shown: %q", row.AgentLatest)
	}
	// Back to a normal agent: the flag is cleared.
	postJSON(t, api+"/checkin", er.Credential, protocol.CheckinRequest{AgentVersion: "0.0.1"}, &cr)
	if d, _ := s.store.DeviceByID(ctx, er.DeviceID); d.Managed != "" {
		t.Fatalf("managed flag not cleared: %q", d.Managed)
	}
}

func TestDeviceRulesForm(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	er := enroll(t, ts, toks[0].Token, protocol.Identity{Hostname: "PC", OS: "windows", Arch: "amd64", HardwareID: "HW"})
	admin, _ := s.store.UserByName(ctx, "admin")
	_ = s.store.SetPassword(ctx, admin.ID, admin.PasswordHash, false)
	adm, _ := login(t, ts, "admin", "initial-password-1")
	// Checked = evaluated: everything except the firewall rule stays on.
	form := url.Values{"form": {"enabled"}}
	for _, def := range RuleCatalog {
		if def.ID != "firewall_off" {
			form.Add("enabled", def.ID)
		}
	}
	adm.post("/devices/"+er.DeviceID+"/rules", form)
	if d, _ := s.store.DeviceByID(ctx, er.DeviceID); len(d.DisabledRules) != 1 || d.DisabledRules[0] != "firewall_off" {
		t.Fatalf("disabled rules: %v", d.DisabledRules)
	}
	_, p := adm.get("/devices/" + er.DeviceID + "?tab=alerts")
	if !strings.Contains(p, `name="enabled" value="firewall_off" >`) || !strings.Contains(p, `name="enabled" value="offline" checked>`) || !strings.Contains(p, "off globally") {
		t.Errorf("rules form does not show checked = evaluated")
	}
}

// A browser that drops the session cookie (BASE_URL https:// but opened via
// http://) gets an explanation instead of a silent login loop.
func TestLoginCookieDropped(t *testing.T) {
	s, ts, _ := newTestServer(t)
	s.cfg.BaseURL = "https://inventory.example.com"
	c := &http.Client{} // no cookie jar: like a browser rejecting the Secure cookie on http://
	resp, err := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"initial-password-1"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	p := html.UnescapeString(string(b))
	if !strings.Contains(p, "did not keep the session cookie") || !strings.Contains(p, "opened via "+ts.URL) || !strings.Contains(p, "BASE_URL is https://inventory.example.com") {
		t.Errorf("no cookie hint on the login page:\n%s", p)
	}
	// With a working cookie the check is invisible.
	s.cfg.BaseURL = ""
	_, body := login(t, ts, "admin", "initial-password-1")
	if strings.Contains(body, "did not keep the session cookie") || !strings.Contains(body, "Change password") {
		t.Errorf("sign-in with cookies did not end on the password page")
	}
}
