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
		"/host/info": map[string]any{"hostname": "homeassistant", "operating_system": "Home Assistant OS 16.3", "kernel": "6.12.47-haos-raspi", "disk_total": 116.7, "disk_used": 20.1, "disk_free": 91.6, "chassis": "embedded", "timezone": "Europe/Berlin"},
		"/network/info": map[string]any{"interfaces": []map[string]any{
			{"interface": "wlan0", "type": "wireless", "connected": true, "primary": false, "ipv4": map[string]any{"method": "static", "nameservers": []string{"192.0.2.53"}},
				"ipv6": map[string]any{"method": "disabled", "nameservers": []string{}}, "wifi": map[string]any{"ssid": "HomeNet"}},
			{"interface": "end0", "type": "ethernet", "connected": true, "primary": true, "ipv4": map[string]any{"method": "auto", "nameservers": []string{"192.0.2.1"}},
				"ipv6": map[string]any{"method": "auto", "nameservers": []string{"2001:db8::1"}}, "wifi": nil},
			{"interface": "eth1", "type": "ethernet", "connected": false, "ipv4": map[string]any{"method": "auto", "nameservers": []string{"198.51.100.1"}}}}},
		"/os/info":   map[string]any{"version": "16.3", "version_latest": "16.3", "update_available": false, "board": "rpi4-64"},
		"/core/info": map[string]any{"version": "2026.11.1", "version_latest": "2026.11.2", "update_available": true},
		"/supervisor/info": map[string]any{"version": "2026.11.0", "version_latest": "2026.11.0", "update_available": false, "addons": []map[string]any{
			{"name": "Mosquitto broker", "slug": "core_mosquitto", "version": "6.5.1", "version_latest": "6.5.2", "update_available": true, "repository": "core"},
			{"name": "Inventory Agent", "slug": "x_inventory_agent", "version": "0.1.0", "version_latest": "0.1.0", "update_available": false, "repository": "x"}}},
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/addons" { // needs the manager role, like the real Supervisor
			http.Error(w, "forbidden", http.StatusForbidden)
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
	if len(sw.Items) != 5 || sw.Items[0].Name != "Home Assistant OS" || sw.Items[2].Name != "Home Assistant Supervisor" || sw.Items[4].Source != "ha-addon" ||
		sw.Items[3].Publisher != "Home Assistant" || sw.Items[4].Publisher != "custom repository" {
		t.Fatalf("software: %+v", sw.Items)
	}

	var host haHostInfo
	var osInfo haVersionInfo
	if err := supervisorGet(ctx, "/host/info", &host); err != nil {
		t.Fatal(err)
	}
	_ = supervisorGet(ctx, "/os/info", &osInfo)
	info := protocol.SystemInfo{OS: protocol.OSInfo{Name: "Alpine Linux v3.22", DistroID: "alpine", Timezone: "Etc/UTC"}, Hardware: protocol.HardwareInfo{Virtual: true},
		Users:   protocol.UsersInfo{Admins: []string{"root"}},
		Volumes: []protocol.Volume{{Mount: "/", SizeBytes: 1}}}
	applyHAHost(&info, host, osInfo)
	if info.OS.Name != "Home Assistant OS 16.3" || info.OS.DistroID != "haos" || info.OS.Kernel != "6.12.47-haos-raspi" || len(info.Users.Admins) != 0 {
		t.Fatalf("os: %+v", info.OS)
	}
	if info.OS.Timezone != "Europe/Berlin" || info.Hardware.Virtual {
		t.Fatalf("timezone/virtual: %q %v", info.OS.Timezone, info.Hardware.Virtual)
	}
	if len(info.Volumes) != 1 || info.Volumes[0].Mount != "/mnt/data" || info.Volumes[0].SizeBytes < 116<<30 {
		t.Fatalf("volumes: %+v", info.Volumes)
	}
	var netInfo haNetworkInfo
	if err := supervisorGet(ctx, "/network/info", &netInfo); err != nil {
		t.Fatal(err)
	}
	info.DNS = []string{"172.30.32.3"}
	info.Network = []protocol.NetAdapter{{Name: "end0", Up: true}, {Name: "wlan0", Up: true, Wireless: true}}
	applyHANetwork(&info, netInfo)
	if strings.Join(info.DNS, ",") != "192.0.2.1,2001:db8::1,192.0.2.53" || info.WiFiSSID != "HomeNet" {
		t.Fatalf("dns/ssid: %v %q", info.DNS, info.WiFiSSID)
	}
	if n := info.Network[0]; n.DHCP == nil || !*n.DHCP || strings.Join(n.DNS, ",") != "192.0.2.1,2001:db8::1" {
		t.Fatalf("end0: %+v", n)
	}
	if n := info.Network[1]; n.DHCP == nil || *n.DHCP {
		t.Fatalf("wlan0 (static): %+v", n)
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

func TestParseCPUInfoRaspberryPi(t *testing.T) {
	pi4 := "processor\t: 0\nBogoMIPS\t: 108.00\nCPU implementer\t: 0x41\nCPU part\t: 0xd08\n\nprocessor\t: 1\nCPU part\t: 0xd08\n\nHardware\t: BCM2835\nRevision\t: d03114\nSerial\t\t: 10000000abcdef01\nModel\t\t: Raspberry Pi 4 Model B Rev 1.4\n"
	model, _, serial := parseCPUInfoText(pi4)
	if model != "ARM Cortex-A72" || serial != "10000000abcdef01" {
		t.Errorf("pi4: model=%q serial=%q", model, serial)
	}
	x86 := "processor\t: 0\nmodel name\t: Intel(R) Core(TM) i5-7300U CPU @ 2.60GHz\nphysical id\t: 0\ncore id\t\t: 0\n"
	if model, cores, _ := parseCPUInfoText(x86); model != "Intel(R) Core(TM) i5-7300U CPU @ 2.60GHz" || cores != 1 {
		t.Errorf("x86: %q %d", model, cores)
	}
}

func TestAddonSystemDisk(t *testing.T) {
	root := t.TempDir()
	dev := filepath.Join(root, "devices", "platform", "usb", "block", "sda")
	for _, p := range []string{"sda1", "sda8"} {
		if err := os.MkdirAll(filepath.Join(dev, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(dev, "uevent"), []byte("MAJOR=8\nMINOR=0\nDEVNAME=sda\nDEVTYPE=disk\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dev, "sda1", "uevent"), []byte("DEVNAME=sda1\nDEVTYPE=partition\nPARTN=1\nPARTNAME=hassos-boot\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dev, "sda8", "uevent"), []byte("DEVNAME=sda8\nDEVTYPE=partition\nPARTN=8\nPARTNAME=hassos-data\n"), 0o644)
	cls := filepath.Join(root, "class", "block")
	_ = os.MkdirAll(cls, 0o755)
	for _, l := range [][2]string{{"sda", dev}, {"sda1", filepath.Join(dev, "sda1")}, {"sda8", filepath.Join(dev, "sda8")}} {
		if err := os.Symlink(l[1], filepath.Join(cls, l[0])); err != nil {
			t.Fatal(err)
		}
	}
	if got := haosDisk(cls, filepath.Join(root, "dev")); got != "sda" {
		t.Fatalf("haosDisk = %q", got)
	}
	// Fallback via the file system label.
	_ = os.WriteFile(filepath.Join(dev, "sda1", "uevent"), []byte("DEVNAME=sda1\nDEVTYPE=partition\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dev, "sda8", "uevent"), []byte("DEVNAME=sda8\nDEVTYPE=partition\n"), 0o644)
	byLabel := filepath.Join(root, "dev", "disk", "by-label")
	_ = os.MkdirAll(byLabel, 0o755)
	_ = os.WriteFile(filepath.Join(root, "dev", "sda8"), nil, 0o644)
	_ = os.Symlink(filepath.Join(root, "dev", "sda8"), filepath.Join(byLabel, "hassos-data"))
	if got := haosDisk(cls, filepath.Join(root, "dev")); got != "sda" {
		t.Fatalf("haosDisk via label = %q", got)
	}

	// smartctl denied: model and size from sysfs, hint about the protection mode.
	_ = os.WriteFile(filepath.Join(dev, "size"), []byte("976773168\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(dev, "device"), 0o755)
	_ = os.WriteFile(filepath.Join(dev, "device", "vendor"), []byte("Samsung \n"), 0o644)
	_ = os.WriteFile(filepath.Join(dev, "device", "model"), []byte("Portable SSD T7   \n"), 0o644)
	denied := []protocol.Disk{{Device: "/dev/sda", Messages: []string{"Smartctl open device: /dev/sda [SAT] failed: Operation not permitted"}}}
	if !addonFillFromSysfs(denied, cls) || denied[0].Model != "Samsung Portable SSD T7" || denied[0].SizeBytes != 976773168*512 {
		t.Fatalf("sysfs fallback: %+v", denied[0])
	}

	// USB SSD with the HAOS partitions next to an empty SD slot and a second USB disk.
	disks := []protocol.Disk{{Device: "/dev/sdb", External: true}, {Device: "/dev/sda", External: true, Bus: "USB"}}
	markAddonSystemDisk(disks, "sda")
	if !disks[1].System || disks[1].External || disks[0].System {
		t.Fatalf("haos disk: %+v", disks)
	}
	// Without partition info: a single USB disk is the system disk, a single internal disk as well.
	disks = []protocol.Disk{{Device: "/dev/sda", External: true}}
	markAddonSystemDisk(disks, "")
	if !disks[0].System || disks[0].External {
		t.Fatalf("single usb disk: %+v", disks)
	}
	disks = []protocol.Disk{{Device: "/dev/mmcblk0"}, {Device: "/dev/sda", External: true}}
	markAddonSystemDisk(disks, "")
	if !disks[0].System || disks[1].System {
		t.Fatalf("single internal disk: %+v", disks)
	}
}
