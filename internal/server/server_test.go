package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/release"
	"github.com/commifreak/inventory/internal/tag"
)

type fakeMailer struct {
	sent  []string
	to    [][]string
	mails []Mail
}

func (m *fakeMailer) Send(_ context.Context, to []string, msg Mail) error {
	m.sent = append(m.sent, msg.Subject)
	m.to = append(m.to, to)
	m.mails = append(m.mails, msg)
	return nil
}

func ptr[T any](v T) *T { return &v }

// writeAgents creates a fake bundled agent version.
func writeAgents(t *testing.T, dir, version string, priv ed25519.PrivateKey) {
	t.Helper()
	vd := filepath.Join(dir, version)
	if err := os.MkdirAll(vd, 0o755); err != nil {
		t.Fatal(err)
	}
	m := release.Manifest{Version: version}
	for _, p := range [][2]string{{"windows", "amd64"}, {"linux", "amd64"}} {
		file := "inventory-agent-" + p[0] + "-" + p[1]
		if p[0] == "windows" {
			file += ".exe"
		}
		content := []byte("MZ fake agent " + version + " " + p[0])
		if err := os.WriteFile(filepath.Join(vd, file), content, 0o755); err != nil {
			t.Fatal(err)
		}
		sum, n, _ := release.HashReader(bytes.NewReader(content))
		m.Binaries = append(m.Binaries, release.Binary{OS: p[0], Arch: p[1], File: file, SHA256: sum, Size: n,
			Signature: release.Sign(priv, p[0], p[1], version, sum)})
	}
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(vd, "manifest.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newTestServer(t *testing.T) (*Server, *httptest.Server, *fakeMailer) {
	t.Helper()
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	writeAgents(t, filepath.Join(dir, "bundled"), "0.1.0", priv)
	cfg := Config{DataDir: filepath.Join(dir, "data"), AgentsDir: filepath.Join(dir, "bundled"), InitialAdminPassword: "initial-password-1",
		LocalLogin: true, SessionLifetime: time.Hour, Version: "test", HAAddonRepo: "https://github.com/Commifreak/inventory-ha-addon"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	fm := &fakeMailer{}
	s.mailer = fm
	s.eol.prods = testEOLCycles()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.store.Close() })
	return s, ts, fm
}

func postJSON(t *testing.T, url, auth string, v any, out any) int {
	t.Helper()
	b, _ := json.Marshal(v)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func sampleReport(now time.Time) protocol.Report {
	return protocol.Report{AgentVersion: "0.0.9", Sections: map[string]protocol.Section{
		protocol.CollectSystem: {CollectedAt: now, Data: protocol.SystemInfo{
			OS: protocol.OSInfo{Family: "windows", Name: "Windows 10 Pro", Version: "10.0.19045.5000", DisplayVersion: "22H2", Arch: "amd64", BootTime: now.Add(-time.Hour)},
			Hardware: protocol.HardwareInfo{Manufacturer: "LENOVO", Model: "ThinkPad", CPU: "Intel i5", MemoryBytes: 16 << 30,
				MemorySlots: 2, MemoryMaxBytes: 64 << 30, MemoryModules: []protocol.MemoryModule{
					{Locator: "DIMM A", Installed: true, SizeBytes: 16 << 30, Type: "DDR4", FormFactor: "SODIMM", SpeedMTs: 3200, ConfiguredMTs: 2933, Manufacturer: "Samsung", PartNumber: "M471A2K43DB1-CWE"},
					{Locator: "DIMM B"}},
				Slots: []protocol.SystemSlot{{Designation: "M.2_2", Type: "M.2 (M key)", Kind: "storage", Width: "x4", Usage: "available"},
					{Designation: "PCIEX16_1", Type: "PCIe Gen4 x16", Kind: "expansion", Width: "x16", Usage: "in use"}},
				StorageControllers: []protocol.StorageController{
					{Name: "Standard SATA AHCI Controller", Type: "SATA (AHCI)", Driver: "storahci", Location: `PCI\VEN_8086&DEV_A352`,
						Ports: []protocol.StoragePort{{Port: "bus 0 · target 0", Occupied: true, Device: "Samsung SSD 870", Path: `\\.\PHYSICALDRIVE0`}}},
					{Name: "Intel SATA (AHCI) controller [8086:a352]", Type: "SATA (AHCI)", PortsComplete: true,
						Ports: []protocol.StoragePort{{Port: "1", Occupied: true, Speed: "6.0 Gbps", Device: "Samsung SSD 870", Path: "/dev/sda"}, {Port: "2"}}}}},
			Volumes: []protocol.Volume{{Mount: "C:", FS: "NTFS", SizeBytes: 500 << 30, FreeBytes: 10 << 30, System: true, Encrypted: ptr(false), Encryption: "BitLocker off"}},
			Network: []protocol.NetAdapter{{Name: "Ethernet", IPs: []string{"192.168.1.10/24", "fe80::1/64"}, Up: true, DHCP: ptr(true)}},
			Users:   protocol.UsersInfo{CurrentUsers: []string{"PC\\anna"}, Admins: []string{"PC\\Administrator", "PC\\anna"}, LastLogons: []protocol.UserLogon{{User: "anna", Time: now}}},
			Security: protocol.SecurityInfo{
				SecureBoot: &protocol.SecureBootInfo{Supported: true, Enabled: true, DBHasWindowsUEFICA2023: ptr(false), ServicingStatus: "NotStarted",
					DBHasMicrosoftUEFICA2023: ptr(false), DBHasMicrosoftUEFICA2011: ptr(false)},
				Defender:   &protocol.DefenderInfo{Present: true, ServiceEnabled: true, AntivirusEnabled: true, RealTimeProtection: false, RunningMode: "Normal", SignatureAgeDays: 1},
				Activation: &protocol.ActivationInfo{Licensed: true, Status: "Licensed"},
			},
		}},
		protocol.CollectSMART: {CollectedAt: now, Data: protocol.SmartData{Source: "smartctl 7.5", Disks: []protocol.Disk{
			{Device: "/dev/sda", Model: "Samsung SSD 870", Serial: "S1", Protocol: "ATA", System: true, HealthPassed: ptr(true), Temperature: ptr(35), Reallocated: ptr(int64(3)),
				Attributes: []protocol.SmartAttribute{{ID: 5, Name: "Reallocated_Sector_Ct", Value: 99, Worst: 99, Threshold: 10, Raw: "3"}}},
			{Device: "/dev/nvme0", Model: "WD SN770", Serial: "N1", Protocol: "NVMe", HealthPassed: ptr(true), PercentUsed: ptr(4), AvailableSpare: ptr(100), SpareThreshold: ptr(10)},
		}}},
		protocol.CollectUpdates: {CollectedAt: now, Data: protocol.UpdatesData{Manager: "Windows Update", PendingCount: 2, RebootRequired: true,
			Pending: []protocol.PendingUpdate{{Title: "2026-11 Cumulative Update", KB: "KB5000001"}},
			History: []protocol.UpdateHistoryEntry{{Title: "KB123", Date: now.Add(-time.Hour), Result: "Failed", HResult: "0x80070002"}}}},
		protocol.CollectSoftware:  {CollectedAt: now, Data: protocol.SoftwareData{Items: []protocol.SoftwareItem{{Name: "7-Zip", Version: "23.01", Source: "registry", Scope: "machine"}, officeItem}}},
		protocol.CollectAutostart: {CollectedAt: now, Data: protocol.AutostartData{Items: []protocol.AutostartItem{{Name: "OneDrive", Command: "onedrive.exe /background", Location: `HKCU\Run`, Enabled: true}}}},
		protocol.CollectEvents: {CollectedAt: now, Data: protocol.EventsData{Since: now.Add(-24 * time.Hour), Events: []protocol.CriticalEvent{
			{Kind: protocol.EventBluescreen, Time: now.Add(-2 * time.Hour), Source: "BugCheck", EventID: 1001, Message: "The computer has rebooted from a bugcheck.", Key: "rec1"},
			{Kind: protocol.EventUndervoltage, Time: now.Add(-3 * time.Hour), Source: "kernel", Message: "hwmon hwmon1: Undervoltage detected!", Key: "uv1"},
			{Kind: protocol.EventDiskError, Time: now.Add(-1 * time.Hour), Source: "disk", EventID: 153, Device: "Disk 1 (not connected)", External: true, Message: "retried", Key: "ext1"},
		}}},
	}}
}

func TestEndToEnd(t *testing.T) {
	s, ts, fm := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	if len(toks) != 1 {
		t.Fatalf("expected default token, got %d", len(toks))
	}
	api := ts.URL + protocol.APIPrefix

	// Invalid token is rejected.
	if code := postJSON(t, api+"/enroll", "", protocol.EnrollRequest{Token: "nope-unknown-token", Identity: protocol.Identity{Hostname: "INTRUDER", OS: "linux", Arch: "amd64"}}, nil); code != http.StatusForbidden {
		t.Fatalf("enroll with bad token: %d", code)
	}
	if resp, err := http.Get(api + "/install/another-bad-token/install.sh"); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("installer with bad token: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	// Both attempts are in the audit log, with only a token prefix.
	audit, _ := s.store.ListAudit(ctx, 10, true, nil)
	var found []string
	for _, a := range audit {
		if strings.HasSuffix(a.Action, ".rejected") {
			found = append(found, a.Action+" "+a.Details)
			if strings.Contains(a.Details, "unknown-token") || strings.Contains(a.Details, "bad-token") {
				t.Errorf("full token logged: %s", a.Details)
			}
		}
	}
	if len(found) != 2 || !strings.Contains(strings.Join(found, "|"), `host "INTRUDER"`) || !strings.Contains(strings.Join(found, "|"), "installer.rejected unknown token anothe…") {
		t.Errorf("rejected attempts not audited: %v", found)
	}

	ident := protocol.Identity{Hostname: "PC-ANNA", OS: "windows", Arch: "amd64", HardwareID: "HW-1", MachineID: "M-1"}
	var er protocol.EnrollResponse
	if code := postJSON(t, api+"/enroll", "", protocol.EnrollRequest{Token: toks[0].Token, Identity: ident, AgentVersion: "0.0.9"}, &er); code != 200 {
		t.Fatalf("enroll: %d", code)
	}
	if er.Credential == "" || er.Config.CheckinIntervalSec == 0 {
		t.Fatalf("bad enroll response %+v", er)
	}

	// Re-enrollment with the same identity keeps the device id.
	var er2 protocol.EnrollResponse
	postJSON(t, api+"/enroll", "", protocol.EnrollRequest{Token: toks[0].Token, Identity: ident, AgentVersion: "0.0.9"}, &er2)
	if er2.DeviceID != er.DeviceID {
		t.Fatalf("re-enroll created a new device: %s vs %s", er2.DeviceID, er.DeviceID)
	}
	if code := postJSON(t, api+"/checkin", er.Credential, protocol.CheckinRequest{AgentVersion: "0.0.9"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("old credential must be invalid after re-enroll: %d", code)
	}
	cred := er2.Credential

	now := time.Now()
	if code := postJSON(t, api+"/report", cred, sampleReport(now), nil); code != 200 {
		t.Fatalf("report: %d", code)
	}

	// Check-in offers the bundled signed agent (ring stable follows latest).
	var cr protocol.CheckinResponse
	if code := postJSON(t, api+"/checkin", cred, protocol.CheckinRequest{AgentVersion: "0.0.9", Identity: ident, AgentTime: now}, &cr); code != 200 {
		t.Fatalf("checkin: %d", code)
	}
	if cr.Update == nil || cr.Update.Version != "0.1.0" || cr.Update.Signature == "" {
		t.Fatalf("expected update offer, got %+v", cr.Update)
	}
	// Download the offered binary.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+cr.Update.URL, nil)
	req.Header.Set("Authorization", "Bearer "+cred)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("binary download: %v %v", err, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if sum, _, _ := release.HashReader(bytes.NewReader(body)); sum != cr.Update.SHA256 {
		t.Fatal("hash mismatch")
	}

	// Pause updates: no offer.
	_ = s.store.PutSetting(ctx, setUpdates, UpdatePolicy{Paused: true, RingVersions: map[string]string{}})
	cr = protocol.CheckinResponse{}
	postJSON(t, api+"/checkin", cred, protocol.CheckinRequest{AgentVersion: "0.0.9"}, &cr)
	if cr.Update != nil {
		t.Fatal("update offered while paused")
	}
	// Manual update works while paused.
	_ = s.store.SetUpdateNow(ctx, er.DeviceID, "0.1.0")
	postJSON(t, api+"/checkin", cred, protocol.CheckinRequest{AgentVersion: "0.0.9"}, &cr)
	if cr.Update == nil {
		t.Fatal("manual update not offered")
	}
	// Reporting the new version clears update-now.
	postJSON(t, api+"/checkin", cred, protocol.CheckinRequest{AgentVersion: "0.1.0", UpdateResult: &protocol.UpdateResult{FromVersion: "0.0.9", ToVersion: "0.1.0", Success: true, Time: now},
		Diagnostics: &protocol.AgentDiagnostics{Proxy: "http://proxy.lan:3128 (WinHTTP (netsh winhttp))", Log: []protocol.AgentLogEntry{
			{Time: now.Add(-time.Hour), Level: "WARN", Message: "report failed err=server returned 502"},
			{Time: now, Level: "ERROR", Message: "update failed to=0.1.1 err=signature mismatch"}}}}, &cr)
	d, _ := s.store.DeviceByID(ctx, er.DeviceID)
	if d.UpdateNowVersion != "" || d.AgentVersion != "0.1.0" {
		t.Fatalf("update-now not cleared: %+v", d)
	}

	// Windows installer carries the tag.
	resp, err = http.Get(api + "/install/" + toks[0].Token + "/windows/inventory-agent-setup-amd64.exe")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("installer: %v %d", err, resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	tg, err := tag.Read(body)
	if err != nil || tg.EnrollmentToken != toks[0].Token || tg.ServerURL != ts.URL {
		t.Fatalf("tag: %+v %v", tg, err)
	}
	resp, _ = http.Get(api + "/install/" + toks[0].Token + "/install.sh")
	sh, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(sh), toks[0].Token) || !strings.Contains(string(sh), "inventory-agent\" install") {
		t.Fatalf("install script: %s", sh)
	}

	// Alerts: SMTP configured -> mail for the new alerts.
	_ = s.store.PutSetting(ctx, setSMTP, SMTPSettings{Host: "localhost", From: "inv@example.com", Port: 25})
	as := s.alertSettings(ctx)
	as.Recipients = []string{"admin@example.com"}
	_ = s.store.PutSetting(ctx, setAlerts, as)
	s.runAlerts(ctx, nil)
	open, _ := s.store.OpenAlerts(ctx)
	rules := map[string]bool{}
	for _, a := range open {
		rules[a.Rule] = true
	}
	for _, want := range []string{"smart_reallocated", "disk_space", "defender_off", "secureboot_certs", "updates_failed", "bluescreen", "os_eol", "office_eol", "undervoltage"} {
		if !rules[want] {
			t.Errorf("expected alert %s, open: %v", want, rules)
		}
	}
	if rules["disk_errors"] {
		t.Errorf("disk error on an external disk raised an alert")
	}
	if len(fm.sent) != 1 {
		t.Fatalf("expected one mail, got %v", fm.sent)
	}
	// Second run: no new mail.
	s.runAlerts(ctx, nil)
	if len(fm.sent) != 1 {
		t.Fatalf("duplicate mails: %v", fm.sent)
	}

	// Software change detection.
	rep := sampleReport(now.Add(time.Minute))
	rep.Sections = map[string]protocol.Section{protocol.CollectSoftware: {CollectedAt: now.Add(time.Minute), Data: protocol.SoftwareData{Items: []protocol.SoftwareItem{
		{Name: "7-Zip", Version: "24.08", Source: "registry", Scope: "machine"}, {Name: "VLC", Version: "3.0", Source: "registry", Scope: "machine"}, officeItem}}}}
	postJSON(t, api+"/report", cred, rep, nil)
	changes, _ := s.store.SoftwareChanges(ctx, er.DeviceID, 10)
	if len(changes) != 2 {
		t.Fatalf("expected 2 software changes, got %+v", changes)
	}

	// --- web UI ---
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, _ = c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"initial-password-1"}})
	resp.Body.Close()
	// Must change the password first.
	page := get(t, c, ts.URL+"/")
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page)
	if len(csrf) < 2 || !strings.Contains(page, "Change password") {
		t.Fatalf("expected password change page")
	}
	resp, _ = c.PostForm(ts.URL+"/account/password", url.Values{"csrf": {csrf[1]}, "current": {"initial-password-1"}, "new": {"a-much-better-password"}, "confirm": {"a-much-better-password"}})
	resp.Body.Close()
	page = get(t, c, ts.URL+"/")
	if !strings.Contains(page, "PC-ANNA") || !strings.Contains(page, "Last report") {
		t.Fatalf("dashboard does not list device")
	}
	if p := get(t, c, ts.URL+"/devices/"+er.DeviceID+"?tab=overview"); !strings.Contains(p, "not applicable") {
		t.Errorf("third-party CA shown as missing although not applicable")
	}
	// Server warning when endoflife.date is unreachable.
	s.eol.mu.Lock()
	s.eol.fetch, s.eol.failures, s.eol.lastErr = true, 2, "connection refused"
	s.eol.mu.Unlock()
	if p := get(t, c, ts.URL+"/"); !strings.Contains(p, "flash warn") || !strings.Contains(p, "connection refused") {
		t.Errorf("endoflife.date warning not shown")
	}
	s.eol.mu.Lock()
	s.eol.fetch, s.eol.failures = false, 0
	s.eol.mu.Unlock()
	if p := get(t, c, ts.URL+"/devices/"+er.DeviceID+"?tab=overview"); !strings.Contains(p, "1 of 2 slots used") || !strings.Contains(p, "M471A2K43DB1-CWE") || !strings.Contains(p, "PCIe Gen4 x16") {
		t.Errorf("memory modules/slots missing on the overview")
	}
	if p := get(t, c, ts.URL+"/devices/"+er.DeviceID+"?tab=disks"); !strings.Contains(p, "Storage controllers") || !strings.Contains(p, "Only occupied ports are known") ||
		!strings.Contains(p, "6.0 Gbps") || !strings.Contains(p, "M.2_2") || strings.Contains(p, "PCIEX16_1") {
		t.Errorf("storage controllers/slots wrong on the disks tab")
	}
	if p := get(t, c, ts.URL+"/devices/"+er.DeviceID+"?tab=software"); !strings.Contains(p, "Office support") || !strings.Contains(p, "ended 2025-10-14") {
		t.Errorf("office support status missing on the software tab")
	}
	if p := get(t, c, ts.URL+"/devices/"+er.DeviceID+"?tab=agent"); !strings.Contains(p, "Agent diagnostics") || !strings.Contains(p, "proxy.lan:3128") ||
		!strings.Contains(p, "signature mismatch") || strings.Index(p, "signature mismatch") > strings.Index(p, "server returned 502") {
		t.Errorf("agent diagnostics missing or not newest first")
	}
	if raw := get(t, c, ts.URL+"/devices/"+er.DeviceID+"/raw.json"); !strings.Contains(raw, `"agent_diagnostics"`) || !strings.Contains(raw, "server returned 502") {
		t.Errorf("raw export lacks agent diagnostics")
	}
	if raw := get(t, c, ts.URL+"/devices/"+er.DeviceID+"/raw.json"); !strings.Contains(raw, `"sections"`) || !strings.Contains(raw, "Samsung SSD 870") {
		t.Errorf("raw export incomplete")
	}
	for _, tab := range []string{"overview", "disks", "updates", "software", "autostart", "events", "alerts", "agent", "raw"} {
		p := get(t, c, ts.URL+"/devices/"+er.DeviceID+"?tab="+tab)
		if !strings.Contains(p, "PC-ANNA") {
			t.Errorf("tab %s does not render device", tab)
		}
	}
	if p := get(t, c, ts.URL+"/settings/install"); !strings.Contains(p, "Add repository to Home Assistant") || !strings.Contains(p, "repository_url=https%3A%2F%2Fgithub.com%2FCommifreak%2Finventory-ha-addon") {
		t.Errorf("Home Assistant install section missing: %s", regexp.MustCompile(`href="https://my[^"]*"`).FindString(p))
	}
	for _, p := range []string{"/alerts", "/settings/install", "/settings/updates", "/settings/collection", "/settings/alerts", "/settings/smtp", "/settings/users", "/settings/general"} {
		get(t, c, ts.URL+p)
	}
	// CSRF is enforced.
	resp, _ = c.PostForm(ts.URL+"/settings/general", url.Values{"instance_name": {"x"}, "retention_days": {"30"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func get(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", url, resp.StatusCode, b)
	}
	return string(b)
}

var officeItem = protocol.SoftwareItem{Name: "Microsoft Office Professional Plus 2016", Version: "16.0.4266.1001", Source: "registry", Scope: "machine", Arch: "x86"}

func TestOfficeLookup(t *testing.T) {
	e := &EOLData{prods: testEOLCycles()}
	sw := func(n string) protocol.SoftwareItem { return protocol.SoftwareItem{Name: n} }
	got := e.OfficeLookup([]protocol.SoftwareItem{
		sw("Microsoft Office LTSC Professional Plus 2021 - de-de"),
		sw("Microsoft Visio Standard 2021 - de-de"),
		sw("Microsoft Office Home and Business 2019 - en-us"),
		sw("Microsoft 365 Apps for business - de-de"),
		sw("Microsoft Teams Meeting Add-in for Microsoft Office"),
		sw("Microsoft Office Proofing Tools 2016 - Deutsch"),
		sw("Microsoft Office 2024 Something"),
		sw("7-Zip 23.01"),
	})
	if len(got) != 3 || got[0].Cycle != "2019" || got[1].Cycle != "2021" || got[2].Cycle != "2024" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if len(got[1].Products) != 2 || got[1].EOL.Format("2006-01-02") != "2026-10-13" {
		t.Errorf("office 2021: %+v", got[1])
	}
	// Releases without data are skipped; no data at all yields nothing.
	if got := e.OfficeLookup([]protocol.SoftwareItem{sw("Microsoft Office Standard 2007")}); len(got) != 0 {
		t.Errorf("release without data reported: %+v", got)
	}
	e = &EOLData{prods: map[string][]eolCycle{}}
	if got := e.OfficeLookup([]protocol.SoftwareItem{sw("Microsoft Office Standard 2021")}); len(got) != 0 {
		t.Errorf("reported without data: %+v", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0}, {"1.0.1", "1.0.0", 1}, {"1.2.0", "1.10.0", -1},
		{"1.0.0-edge.20261117", "1.0.0", -1}, {"1.0.0-edge.2", "1.0.0-edge.10", -1}, {"v2.0.0", "1.9.9", 1}, {"dev", "0.1.0", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
