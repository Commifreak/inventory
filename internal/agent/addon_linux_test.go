package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/commifreak/inventory/internal/protocol"
)

func fakeSupervisor(t *testing.T) *httptest.Server {
	t.Helper()
	data := map[string]any{
		"/host/info":       map[string]any{"hostname": "homeassistant", "operating_system": "Home Assistant OS 16.3", "kernel": "6.12.47-haos-raspi", "disk_total": 116.7, "disk_used": 20.1, "disk_free": 91.6},
		"/os/info":         map[string]any{"version": "16.3", "version_latest": "16.3", "update_available": false, "board": "rpi4-64"},
		"/core/info":       map[string]any{"version": "2026.11.1", "version_latest": "2026.11.2", "update_available": true},
		"/supervisor/info": map[string]any{"version": "2026.11.0", "version_latest": "2026.11.0", "update_available": false},
		"/addons": map[string]any{"addons": []map[string]any{
			{"name": "Mosquitto broker", "slug": "core_mosquitto", "version": "6.5.1", "version_latest": "6.5.2", "update_available": true, "repository": "core"},
			{"name": "Inventory Agent", "slug": "x_inventory_agent", "version": "0.1.0", "version_latest": "0.1.0", "update_available": false, "repository": "x"}}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		d, ok := data[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": "ok", "data": d})
	}))
}

func setupAddon(t *testing.T, opts string) {
	t.Helper()
	dir := t.TempDir()
	oldData, oldOpts, oldURL := addonDataDir, addonOptions, supervisorURL
	addonDataDir, addonOptions = filepath.Join(dir, "agent"), filepath.Join(dir, "options.json")
	t.Cleanup(func() { addonDataDir, addonOptions, supervisorURL, addonMode = oldData, oldOpts, oldURL, false })
	_ = os.WriteFile(addonOptions, []byte(opts), 0o600)
	t.Setenv("SUPERVISOR_TOKEN", "test-token")
}

func TestAddonPrepare(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	setupAddon(t, `{"server_url": "https://inv.example.com/", "enrollment_token": "tok-1"}`)
	if err := prepareAddon(log); err != nil {
		t.Fatal(err)
	}
	if DataDir() != addonDataDir || managedBy() != ManagedHomeAssistant {
		t.Fatalf("add-on mode not active: %s %q", DataDir(), managedBy())
	}
	cfg, err := LoadConfig()
	if err != nil || cfg.ServerURL != "https://inv.example.com" || cfg.EnrollmentToken != "tok-1" {
		t.Fatalf("config: %+v %v", cfg, err)
	}
	// Enrolled: a restart keeps the credential even though the token is still in the options.
	cfg.Credential, cfg.DeviceID, cfg.EnrollmentToken = "secret", "dev1", ""
	_ = SaveConfig(cfg)
	if err := prepareAddon(log); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := LoadConfig(); cfg.Credential != "secret" {
		t.Fatalf("credential lost on restart: %+v", cfg)
	}
	// The server rejects the credential (device deleted): enroll again with the options token.
	a := &Agent{cfg: cfg, client: NewClient(cfg.ServerURL, cfg.Credential)}
	if !a.reEnrollFromOptions() || a.cfg.Credential != "" || a.cfg.EnrollmentToken != "tok-1" {
		t.Fatalf("re-enrollment not prepared: %+v", a.cfg)
	}
	// Machine ID is persistent.
	if id1, id2 := addonMachineID(), addonMachineID(); id1 == "" || id1 != id2 {
		t.Fatalf("machine id not stable: %q %q", id1, id2)
	}

	// Missing server URL or token is reported.
	setupAddon(t, `{"server_url": "", "enrollment_token": ""}`)
	if err := prepareAddon(log); err == nil || !strings.Contains(err.Error(), "server_url") {
		t.Fatalf("expected server_url error, got %v", err)
	}
	setupAddon(t, `{"server_url": "https://inv.example.com", "enrollment_token": ""}`)
	if err := prepareAddon(log); err == nil || !strings.Contains(err.Error(), "enrollment_token") {
		t.Fatalf("expected token error, got %v", err)
	}
}

func TestAddonSupervisorCollectors(t *testing.T) {
	setupAddon(t, `{}`)
	sv := fakeSupervisor(t)
	defer sv.Close()
	supervisorURL = sv.URL
	ctx := context.Background()

	v, warns, err := collectUpdatesAddon(ctx, nil)
	if err != nil || len(warns) != 0 {
		t.Fatalf("updates: %v %v", err, warns)
	}
	u := v.(protocol.UpdatesData)
	if u.PendingCount != 2 || !strings.Contains(u.Pending[0].Title, "Home Assistant Core 2026.11.1 → 2026.11.2") || !strings.Contains(u.Pending[1].Title, "Mosquitto broker 6.5.1 → 6.5.2") {
		t.Fatalf("pending: %+v", u.Pending)
	}

	v, _, err = collectSoftwareAddon(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	sw := v.(protocol.SoftwareData)
	if len(sw.Items) != 5 || sw.Items[0].Name != "Home Assistant OS" || sw.Items[4].Source != "ha-addon" {
		t.Fatalf("software: %+v", sw.Items)
	}

	var host haHostInfo
	var osInfo haVersionInfo
	if err := supervisorGet(ctx, "/host/info", &host); err != nil {
		t.Fatal(err)
	}
	_ = supervisorGet(ctx, "/os/info", &osInfo)
	info := protocol.SystemInfo{OS: protocol.OSInfo{Name: "Alpine Linux v3.22", DistroID: "alpine"}, Users: protocol.UsersInfo{Admins: []string{"root"}},
		Volumes: []protocol.Volume{{Mount: "/", SizeBytes: 1}}}
	applyHAHost(&info, host, osInfo)
	if info.OS.Name != "Home Assistant OS 16.3" || info.OS.DistroID != "haos" || info.OS.Kernel != "6.12.47-haos-raspi" || len(info.Users.Admins) != 0 {
		t.Fatalf("os: %+v", info.OS)
	}
	if len(info.Volumes) != 1 || info.Volumes[0].Mount != "/mnt/data" || info.Volumes[0].SizeBytes < 116<<30 {
		t.Fatalf("volumes: %+v", info.Volumes)
	}
	if addonHostname() != "homeassistant" {
		t.Fatalf("hostname: %s", addonHostname())
	}

	// Wrong token: errors are reported.
	t.Setenv("SUPERVISOR_TOKEN", "wrong")
	if _, _, err := collectUpdatesAddon(ctx, nil); err == nil {
		t.Fatal("expected an error without Supervisor access")
	}
}
