package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// Home Assistant add-on mode: the agent runs as a Home Assistant add-on
// (a container managed by the Supervisor). Configuration comes from the
// add-on options, data lives in the add-on's persistent /data volume, updates
// are delivered as new add-on versions (no self-update), and OS, update and
// software information comes from the Supervisor API instead of the
// container's own OS.

// ManagedHomeAssistant marks agents updated by Home Assistant.
const ManagedHomeAssistant = "home-assistant"

var (
	addonMode      bool
	addonDataDir   = "/data/agent"
	addonOptions   = "/data/options.json"
	supervisorURL  = "http://supervisor"
	supervisorHTTP = &http.Client{Timeout: 30 * time.Second}
)

type haOptions struct {
	ServerURL       string `json:"server_url"`
	EnrollmentToken string `json:"enrollment_token"`
}

func readAddonOptions() (haOptions, error) {
	var o haOptions
	b, err := os.ReadFile(addonOptions)
	if err != nil {
		return o, err
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return o, err
	}
	o.ServerURL = strings.TrimRight(strings.TrimSpace(o.ServerURL), "/")
	o.EnrollmentToken = strings.TrimSpace(o.EnrollmentToken)
	return o, nil
}

// RunAddon runs the agent as a Home Assistant add-on.
func RunAddon(ctx context.Context, log *slog.Logger) error {
	if err := prepareAddon(log); err != nil {
		return err
	}
	return Run(ctx, log)
}

// prepareAddon switches to add-on mode and writes the agent configuration
// from the add-on options when needed.
func prepareAddon(log *slog.Logger) error {
	if os.Getenv("SUPERVISOR_TOKEN") == "" {
		return errors.New("not running as a Home Assistant add-on (SUPERVISOR_TOKEN is not set)")
	}
	opts, err := readAddonOptions()
	if err != nil {
		return fmt.Errorf("read add-on options: %w", err)
	}
	if opts.ServerURL == "" {
		return errors.New("set server_url in the add-on configuration")
	}
	addonMode = true
	if err := os.MkdirAll(addonDataDir, 0o700); err != nil {
		return err
	}
	cfg, err := LoadConfig()
	switch {
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("load config: %w", err)
	case err != nil || cfg.ServerURL != opts.ServerURL:
		// First start or another server: enroll with the configured token.
		if opts.EnrollmentToken == "" {
			return errors.New("set enrollment_token in the add-on configuration (Inventory server: Settings → Install agents)")
		}
		if err := SaveConfig(&Config{ServerURL: opts.ServerURL, EnrollmentToken: opts.EnrollmentToken}); err != nil {
			return err
		}
		log.Info("configured from add-on options", "server", opts.ServerURL)
	}
	return nil
}

// reEnrollFromOptions prepares a new enrollment with the token of the add-on
// options after the server rejected the credential (device deleted).
func (a *Agent) reEnrollFromOptions() bool {
	if !addonMode {
		return false
	}
	opts, err := readAddonOptions()
	if err != nil || opts.EnrollmentToken == "" || opts.ServerURL != a.cfg.ServerURL {
		return false
	}
	a.cfg.Credential, a.cfg.DeviceID, a.cfg.EnrollmentToken = "", "", opts.EnrollmentToken
	if SaveConfig(a.cfg) != nil {
		return false
	}
	a.client.Credential = ""
	return true
}

func managedBy() string {
	if addonMode {
		return ManagedHomeAssistant
	}
	return ""
}

// supervisorGet calls the Supervisor API and decodes its "data" member.
func supervisorGet(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, supervisorURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("SUPERVISOR_TOKEN"))
	resp, err := supervisorHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("supervisor %s: HTTP %d", path, resp.StatusCode)
	}
	var env struct {
		Result  string          `json:"result"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("supervisor %s: %w", path, err)
	}
	if env.Result != "ok" {
		return fmt.Errorf("supervisor %s: %s", path, env.Message)
	}
	return json.Unmarshal(env.Data, out)
}

type haVersionInfo struct {
	Version         string `json:"version"`
	VersionLatest   string `json:"version_latest"`
	UpdateAvailable bool   `json:"update_available"`
	Board           string `json:"board"`
}

type haHostInfo struct {
	Hostname        string  `json:"hostname"`
	OperatingSystem string  `json:"operating_system"`
	Kernel          string  `json:"kernel"`
	Chassis         string  `json:"chassis"`
	Timezone        string  `json:"timezone"`
	DiskTotal       float64 `json:"disk_total"` // GiB
	DiskUsed        float64 `json:"disk_used"`
	DiskFree        float64 `json:"disk_free"`
}

// haSupervisorInfo is /supervisor/info, which also lists the installed
// add-ons (the /addons endpoint needs the "manager" role).
type haSupervisorInfo struct {
	haVersionInfo
	Addons []haAddon `json:"addons"`
}

type haAddon struct {
	Name            string `json:"name"`
	Slug            string `json:"slug"`
	Version         string `json:"version"`
	VersionLatest   string `json:"version_latest"`
	UpdateAvailable bool   `json:"update_available"`
	Repository      string `json:"repository"`
	State           string `json:"state"`
}

// haNetworkInfo is /network/info: the host's interfaces as NetworkManager
// sees them. The container only knows the Supervisor's internal DNS.
type haNetworkInfo struct {
	Interfaces []haInterface `json:"interfaces"`
}

type haInterface struct {
	Interface string     `json:"interface"`
	Type      string     `json:"type"` // ethernet, wireless, vlan
	Connected bool       `json:"connected"`
	Primary   bool       `json:"primary"`
	IPv4      haIPConfig `json:"ipv4"`
	IPv6      haIPConfig `json:"ipv6"`
	WiFi      *struct {
		SSID string `json:"ssid"`
	} `json:"wifi"`
}

type haIPConfig struct {
	Method      string   `json:"method"` // auto, static, disabled
	Nameservers []string `json:"nameservers"`
}

var (
	haHostMu     sync.Mutex
	haHostCached haHostInfo
)

// addonHostname returns the host name of the Home Assistant host.
func addonHostname() string {
	haHostMu.Lock()
	defer haHostMu.Unlock()
	if haHostCached.Hostname == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var h haHostInfo
		if supervisorGet(ctx, "/host/info", &h) == nil {
			haHostCached = h
		}
	}
	if haHostCached.Hostname != "" {
		return haHostCached.Hostname
	}
	h, _ := os.Hostname()
	return h
}

// addonMachineID is a random ID kept in the persistent add-on data; the
// container's /etc/machine-id changes with every image.
func addonMachineID() string {
	p := filepath.Join(addonDataDir, "machine-id")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		return strings.TrimSpace(string(b))
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	id := hex.EncodeToString(buf)
	_ = writeFileAtomic(p, []byte(id+"\n"), 0o600)
	return id
}

// addonHardwareID identifies the hardware: DMI UUID (x86) or the board
// serial number (Raspberry Pi and other device-tree boards).
func addonHardwareID() string {
	if id := cleanID(readTrim("/sys/class/dmi/id/product_uuid")); id != "" {
		return strings.ToUpper(id)
	}
	if s := strings.Trim(readTrim("/proc/device-tree/serial-number"), "\x00 "); s != "" {
		return "DT-" + strings.ToUpper(s)
	}
	if _, _, serial := parseCPUInfo(); serial != "" {
		return "CPU-" + strings.ToUpper(serial)
	}
	return ""
}

func addonCollectors() map[string]Collector {
	return map[string]Collector{
		protocol.CollectSystem:   collectSystemAddon,
		protocol.CollectSMART:    collectSmartAddon,
		protocol.CollectUpdates:  collectUpdatesAddon,
		protocol.CollectSoftware: collectSoftwareAddon,
		protocol.CollectEvents:   collectEventsLinux,
	}
}

// collectSystemAddon reuses the Linux collector (hardware, network and
// Raspberry Pi data come from the host's /sys and /proc) and replaces what
// belongs to the container with data from the Supervisor.
func collectSystemAddon(ctx context.Context, st *State) (any, []string, error) {
	v, warns, err := collectSystemLinux(ctx, st)
	if err != nil {
		return v, warns, err
	}
	info := v.(protocol.SystemInfo)
	var host haHostInfo
	if err := supervisorGet(ctx, "/host/info", &host); err != nil {
		warns = append(warns, "supervisor host info: "+err.Error())
	} else {
		haHostMu.Lock()
		haHostCached = host
		haHostMu.Unlock()
	}
	var osInfo haVersionInfo
	if err := supervisorGet(ctx, "/os/info", &osInfo); err != nil {
		warns = append(warns, "supervisor os info: "+err.Error())
	}
	applyHAHost(&info, host, osInfo)
	var netInfo haNetworkInfo
	if err := supervisorGet(ctx, "/network/info", &netInfo); err != nil {
		warns = append(warns, "supervisor network info: "+err.Error())
	} else {
		applyHANetwork(&info, netInfo)
	}
	return info, warns, nil
}

// applyHANetwork replaces the container's DNS (the Supervisor's internal
// resolver) with the host's name servers and adds DHCP and Wi-Fi details.
func applyHANetwork(info *protocol.SystemInfo, n haNetworkInfo) {
	var dns []string
	addDNS := func(list []string) {
		for _, d := range list {
			if d != "" && !slices.Contains(dns, d) {
				dns = append(dns, d)
			}
		}
	}
	// Primary interface first.
	ifaces := slices.Clone(n.Interfaces)
	slices.SortStableFunc(ifaces, func(a, b haInterface) int {
		switch {
		case a.Primary == b.Primary:
			return 0
		case a.Primary:
			return -1
		}
		return 1
	})
	for _, it := range ifaces {
		if !it.Connected {
			continue
		}
		ifDNS := append(slices.Clone(it.IPv4.Nameservers), it.IPv6.Nameservers...)
		addDNS(ifDNS)
		if it.WiFi != nil && it.WiFi.SSID != "" && info.WiFiSSID == "" {
			info.WiFiSSID = it.WiFi.SSID
		}
		for i := range info.Network {
			a := &info.Network[i]
			if a.Name != it.Interface {
				continue
			}
			if len(ifDNS) > 0 {
				a.DNS = ifDNS
			}
			if it.IPv4.Method == "auto" || it.IPv4.Method == "static" {
				dhcp := it.IPv4.Method == "auto"
				a.DHCP = &dhcp
			}
		}
	}
	if len(dns) > 0 {
		info.DNS = dns
	}
}

func applyHAHost(info *protocol.SystemInfo, host haHostInfo, osInfo haVersionInfo) {
	name := host.OperatingSystem
	if name == "" && osInfo.Version != "" {
		name = "Home Assistant OS " + osInfo.Version
	}
	if name != "" {
		info.OS.Name = name
	}
	if osInfo.Version != "" {
		info.OS.Version, info.OS.DistroVersion, info.OS.DistroID = osInfo.Version, osInfo.Version, "haos"
	} else if host.OperatingSystem != "" {
		info.OS.DistroID = "homeassistant"
	}
	info.OS.Codename = ""
	if host.Kernel != "" {
		info.OS.Kernel = host.Kernel
	}
	if osInfo.Board != "" && info.Hardware.Model == "" {
		info.Hardware.Model = osInfo.Board
	}
	if host.Timezone != "" {
		info.OS.Timezone = host.Timezone
	}
	// The container itself is detected as virtual; the host is a VM only if
	// Home Assistant says so.
	if host.Chassis != "" {
		info.Hardware.Virtual = host.Chassis == "vm"
	}
	// The container's file systems and accounts say nothing about the host.
	info.Users = protocol.UsersInfo{}
	info.Volumes = nil
	if host.DiskTotal > 0 {
		const gib = 1 << 30
		info.Volumes = []protocol.Volume{{Mount: "/mnt/data", Label: "Home Assistant data", System: true,
			SizeBytes: uint64(host.DiskTotal * gib), FreeBytes: uint64(host.DiskFree * gib)}}
	}
}

// collectUpdatesAddon lists available updates of Home Assistant OS, Core,
// Supervisor and the installed add-ons.
func collectUpdatesAddon(ctx context.Context, _ *State) (any, []string, error) {
	u := protocol.UpdatesData{Manager: "Home Assistant Supervisor", Source: "Home Assistant", LastSearch: time.Now()}
	var warns []string
	ok := 0
	for _, c := range []struct{ path, name string }{{"/os/info", "Home Assistant OS"}, {"/core/info", "Home Assistant Core"}} {
		var v haVersionInfo
		if err := supervisorGet(ctx, c.path, &v); err != nil {
			warns = append(warns, err.Error())
			continue
		}
		ok++
		if v.UpdateAvailable {
			u.Pending = append(u.Pending, protocol.PendingUpdate{Title: fmt.Sprintf("%s %s → %s", c.name, v.Version, v.VersionLatest),
				Version: v.VersionLatest, Category: "Home Assistant"})
		}
	}
	var sup haSupervisorInfo
	if err := supervisorGet(ctx, "/supervisor/info", &sup); err != nil {
		warns = append(warns, err.Error())
	} else {
		ok++
		if sup.UpdateAvailable {
			u.Pending = append(u.Pending, protocol.PendingUpdate{Title: fmt.Sprintf("Home Assistant Supervisor %s → %s", sup.Version, sup.VersionLatest),
				Version: sup.VersionLatest, Category: "Home Assistant"})
		}
		for _, a := range sup.Addons {
			if a.UpdateAvailable {
				u.Pending = append(u.Pending, protocol.PendingUpdate{Title: fmt.Sprintf("Add-on %s %s → %s", a.Name, a.Version, a.VersionLatest),
					Version: a.VersionLatest, Category: "Add-ons"})
			}
		}
	}
	if ok == 0 {
		return nil, warns, errors.New("Supervisor API not reachable")
	}
	u.PendingCount = len(u.Pending)
	return u, warns, nil
}

// collectSoftwareAddon lists Home Assistant components and add-ons.
func collectSoftwareAddon(ctx context.Context, _ *State) (any, []string, error) {
	var items []protocol.SoftwareItem
	var warns []string
	add := func(name, version string) {
		if version != "" {
			items = append(items, protocol.SoftwareItem{Name: name, Version: version, Publisher: "Home Assistant", Source: "home-assistant", Scope: "machine"})
		}
	}
	for _, c := range []struct{ path, name string }{{"/os/info", "Home Assistant OS"}, {"/core/info", "Home Assistant Core"}} {
		var v haVersionInfo
		if err := supervisorGet(ctx, c.path, &v); err != nil {
			warns = append(warns, err.Error())
			continue
		}
		add(c.name, v.Version)
	}
	var sup haSupervisorInfo
	if err := supervisorGet(ctx, "/supervisor/info", &sup); err != nil {
		if len(items) == 0 {
			return nil, warns, err
		}
		warns = append(warns, err.Error())
	}
	add("Home Assistant Supervisor", sup.Version)
	for _, a := range sup.Addons {
		items = append(items, protocol.SoftwareItem{Name: a.Name, Version: a.Version, Publisher: addonPublisher(a.Repository), Source: "ha-addon", Scope: "machine"})
	}
	return protocol.SoftwareData{Items: items}, warns, nil
}

// addonPublisher names the repository of an add-on. Custom repositories are
// identified by a hash only; their names need the "manager" role.
func addonPublisher(repo string) string {
	switch repo {
	case "core":
		return "Home Assistant"
	case "local":
		return "local add-on"
	case "":
		return ""
	}
	return "custom repository"
}

// collectSmartAddon marks the system disk, which the container cannot see
// mounted: the disk holding the Home Assistant OS partitions (GPT names
// "hassos-*" or the file system label "hassos-data"). That disk is the
// system disk even when it is attached via USB (SSD on a Raspberry Pi).
// Without such partitions a single internal disk is assumed to be it.
func collectSmartAddon(ctx context.Context, st *State) (any, []string, error) {
	v, warns, err := collectSmartLinux(ctx, st)
	if err != nil || v == nil {
		return v, warns, err
	}
	sd := v.(protocol.SmartData)
	markAddonSystemDisk(sd.Disks, haosDisk(addonSysBlock, addonDevDir))
	if addonFillFromSysfs(sd.Disks, addonSysBlock) {
		// Device access is denied while the add-on runs in protection mode:
		// full_access only applies to unprotected add-ons.
		warns = append(warns, "SMART access denied: turn off the Protection mode of the Inventory Agent add-on in Home Assistant (Settings → Add-ons → Inventory Agent) and restart it")
	}
	return sd, warns, nil
}

// addonFillFromSysfs completes disks that smartctl could not open with
// model and size from sysfs. It reports whether access was denied.
func addonFillFromSysfs(disks []protocol.Disk, sysBlock string) (denied bool) {
	for i := range disks {
		d := &disks[i]
		for _, m := range d.Messages {
			if strings.Contains(m, "Operation not permitted") || strings.Contains(m, "Permission denied") {
				denied = true
			}
		}
		name := strings.TrimPrefix(d.Device, "/dev/")
		if d.Model == "" {
			vendor := readTrim(filepath.Join(sysBlock, name, "device", "vendor"))
			model := readTrim(filepath.Join(sysBlock, name, "device", "model"))
			d.Model = strings.TrimSpace(strings.TrimSpace(vendor) + " " + strings.TrimSpace(model))
		}
		if d.SizeBytes == 0 {
			if sectors, err := strconv.ParseUint(readTrim(filepath.Join(sysBlock, name, "size")), 10, 64); err == nil {
				d.SizeBytes = sectors * 512
			}
		}
	}
	return denied
}

// Paths for haosDisk (relocatable for tests).
var (
	addonSysBlock = "/sys/class/block"
	addonDevDir   = "/dev"
)

func markAddonSystemDisk(disks []protocol.Disk, haos string) {
	if haos != "" {
		for i := range disks {
			if disks[i].Device == "/dev/"+haos {
				for j := range disks {
					disks[j].System = false
				}
				disks[i].System, disks[i].External = true, false
				return
			}
		}
	}
	internal, count := -1, 0
	for i, d := range disks {
		if d.System {
			return
		}
		if !d.External {
			internal, count = i, count+1
		}
	}
	switch {
	case count == 1:
		disks[internal].System = true
	case count == 0 && len(disks) == 1:
		// Only a USB disk: Home Assistant OS boots from it.
		disks[0].System, disks[0].External = true, false
	}
}

// haosDisk returns the name of the disk ("sda", "mmcblk0", "nvme0n1") that
// holds the Home Assistant OS partitions, or "".
func haosDisk(sysBlock, devDir string) string {
	parent := func(part string) string {
		real, err := filepath.EvalSymlinks(filepath.Join(sysBlock, part))
		if err != nil {
			return ""
		}
		return filepath.Base(filepath.Dir(real))
	}
	entries, _ := os.ReadDir(sysBlock)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(sysBlock, e.Name(), "uevent"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if name, ok := strings.CutPrefix(line, "PARTNAME="); ok && strings.HasPrefix(name, "hassos-") {
				if d := parent(e.Name()); d != "" {
					return d
				}
			}
		}
	}
	if real, err := filepath.EvalSymlinks(filepath.Join(devDir, "disk", "by-label", "hassos-data")); err == nil {
		return parent(filepath.Base(real))
	}
	return ""
}
