package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

func platformCollectors() map[string]Collector {
	return map[string]Collector{
		protocol.CollectSystem:    collectSystemDarwin,
		protocol.CollectSMART:     collectSmartDarwin,
		protocol.CollectUpdates:   collectUpdatesDarwin,
		protocol.CollectSoftware:  collectSoftwareDarwin,
		protocol.CollectAutostart: collectAutostartDarwin,
		protocol.CollectEvents:    collectEventsDarwin,
	}
}

func ioregValue(out, key string) string {
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(key) + `" = "?([^"\n]*)"?`)
	if m := re.FindStringSubmatch(out); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// Identity identifies this machine.
func Identity() protocol.Identity {
	h, _ := os.Hostname()
	id := protocol.Identity{Hostname: h, OS: protocol.OSDarwin, Arch: runtime.GOARCH}
	if out, err := runCmd(context.Background(), "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
		id.HardwareID = strings.ToUpper(cleanID(ioregValue(out, "IOPlatformUUID")))
		id.MachineID = id.HardwareID
	}
	return id
}

// BootTime returns the system boot time.
func BootTime() time.Time {
	out, err := runCmd(context.Background(), "sysctl", "-n", "kern.boottime")
	if err != nil {
		return time.Time{}
	}
	if m := regexp.MustCompile(`sec = (\d+)`).FindStringSubmatch(out); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return time.Unix(n, 0)
	}
	return time.Time{}
}

func sysctl(ctx context.Context, name string) string {
	out, _ := runCmd(ctx, "sysctl", "-n", name)
	return strings.TrimSpace(out)
}

func collectSystemDarwin(ctx context.Context, _ *State) (any, []string, error) {
	var warns []string
	info := protocol.SystemInfo{}
	name, _ := runCmd(ctx, "sw_vers", "-productName")
	ver, _ := runCmd(ctx, "sw_vers", "-productVersion")
	build, _ := runCmd(ctx, "sw_vers", "-buildVersion")
	info.OS = protocol.OSInfo{Family: protocol.OSDarwin, Name: strings.TrimSpace(name) + " " + strings.TrimSpace(ver), Version: strings.TrimSpace(ver),
		Build: strings.TrimSpace(build), Kernel: sysctl(ctx, "kern.osrelease"), Arch: runtime.GOARCH, BootTime: BootTime()}
	if tz, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(tz, "zoneinfo/"); i >= 0 {
			info.OS.Timezone = tz[i+9:]
		}
	}
	mem, _ := strconv.ParseUint(sysctl(ctx, "hw.memsize"), 10, 64)
	cores, _ := strconv.Atoi(sysctl(ctx, "hw.physicalcpu"))
	threads, _ := strconv.Atoi(sysctl(ctx, "hw.logicalcpu"))
	info.Hardware = protocol.HardwareInfo{Manufacturer: "Apple", Model: sysctl(ctx, "hw.model"), CPU: sysctl(ctx, "machdep.cpu.brand_string"),
		CPUCores: cores, CPUThreads: threads, MemoryBytes: mem}
	if out, err := runCmd(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
		info.Hardware.SerialNumber = ioregValue(out, "IOPlatformSerialNumber")
		info.Hardware.UUID = ioregValue(out, "IOPlatformUUID")
	}
	if out, err := runCmd(ctx, "system_profiler", "SPHardwareDataType", "-json"); err == nil {
		var r struct {
			HW []map[string]any `json:"SPHardwareDataType"`
		}
		if json.Unmarshal([]byte(out), &r) == nil && len(r.HW) > 0 {
			if v, ok := r.HW[0]["machine_name"].(string); ok {
				info.Hardware.Model = v + " (" + info.Hardware.Model + ")"
			}
			if v, ok := r.HW[0]["chip_type"].(string); ok && info.Hardware.CPU == "" {
				info.Hardware.CPU = v
			}
		}
	}

	// Volumes
	fv := ""
	if out, err := runCmd(ctx, "fdesetup", "status"); err == nil {
		fv = strings.TrimSpace(out)
	}
	mounts := []string{"/"}
	vols, _ := filepath.Glob("/Volumes/*")
	mounts = append(mounts, vols...)
	seen := map[string]bool{}
	for _, m := range mounts {
		var st syscall.Statfs_t
		if syscall.Statfs(m, &st) != nil {
			continue
		}
		dev := string(bytesToString(st.Mntfromname[:]))
		if seen[dev] || st.Blocks == 0 {
			continue
		}
		seen[dev] = true
		v := protocol.Volume{Mount: string(bytesToString(st.Mntonname[:])), FS: string(bytesToString(st.Fstypename[:])), Device: dev,
			SizeBytes: st.Blocks * uint64(st.Bsize), FreeBytes: st.Bavail * uint64(st.Bsize), System: m == "/"}
		if v.System && fv != "" {
			on := strings.Contains(fv, "FileVault is On")
			v.Encrypted = boolPtr(on)
			v.Encryption = "FileVault " + map[bool]string{true: "on", false: "off"}[on]
		}
		info.Volumes = append(info.Volumes, v)
	}

	// Network
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || strings.HasPrefix(ifc.Name, "utun") || strings.HasPrefix(ifc.Name, "awdl") || strings.HasPrefix(ifc.Name, "llw") || strings.HasPrefix(ifc.Name, "bridge") {
			continue
		}
		a := protocol.NetAdapter{Name: ifc.Name, MAC: ifc.HardwareAddr.String(), Up: ifc.Flags&net.FlagUp != 0}
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			a.IPs = append(a.IPs, ad.String())
		}
		if len(a.IPs) > 0 {
			info.Network = append(info.Network, a)
		}
	}
	if out, err := runCmd(ctx, "route", "-n", "get", "default"); err == nil {
		if m := regexp.MustCompile(`gateway: (\S+)`).FindStringSubmatch(out); m != nil {
			info.Gateways = []string{m[1]}
		}
	}
	if out, err := runCmd(ctx, "scutil", "--dns"); err == nil {
		for _, m := range regexp.MustCompile(`nameserver\[\d+\] : (\S+)`).FindAllStringSubmatch(out, -1) {
			info.DNS = append(info.DNS, m[1])
		}
		info.DNS = uniqueStrings(info.DNS)
	}

	// Users
	if out, err := runCmd(ctx, "who"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) > 0 {
				info.Users.CurrentUsers = append(info.Users.CurrentUsers, f[0])
			}
		}
		info.Users.CurrentUsers = uniqueStrings(info.Users.CurrentUsers)
	}
	if out, err := runCmd(ctx, "dscl", ".", "-read", "/Groups/admin", "GroupMembership"); err == nil {
		f := strings.Fields(out)
		if len(f) > 1 {
			info.Users.Admins = f[1:]
		}
		info.Users.AdminGroup = "admin"
	}
	if out, err := runCmd(ctx, "last", "-100"); err == nil {
		latest := map[string]protocol.UserLogon{}
		re := regexp.MustCompile(`(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (\w{3}) +(\d+) (\d\d:\d\d)`)
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) < 3 || f[0] == "reboot" || f[0] == "shutdown" || f[0] == "wtmp" {
				continue
			}
			m := re.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			t, err := time.ParseInLocation("Jan 2 15:04 2006", fmt.Sprintf("%s %s %s %d", m[2], m[3], m[4], time.Now().Year()), time.Local)
			if err != nil {
				continue
			}
			if t.After(time.Now()) {
				t = t.AddDate(-1, 0, 0)
			}
			if cur, ok := latest[f[0]]; !ok || t.After(cur.Time) {
				latest[f[0]] = protocol.UserLogon{User: f[0], Time: t}
			}
		}
		for _, v := range latest {
			info.Users.LastLogons = append(info.Users.LastLogons, v)
		}
		sort.Slice(info.Users.LastLogons, func(i, j int) bool { return info.Users.LastLogons[i].Time.After(info.Users.LastLogons[j].Time) })
	}

	// Battery
	if out, err := runCmd(ctx, "ioreg", "-rn", "AppleSmartBattery"); err == nil && strings.Contains(out, "DesignCapacity") {
		num := func(k string) float64 { v, _ := strconv.ParseFloat(ioregValue(out, k), 64); return v }
		design, full := num("DesignCapacity"), num("AppleRawMaxCapacity")
		if full == 0 {
			full = num("MaxCapacity")
		}
		volt := num("Voltage") / 1000 // mV -> V, capacities are mAh
		if design > 0 {
			b := protocol.Battery{Name: "Internal battery", DesignCapacity: design * volt, FullChargeCapacity: full * volt, HealthPercent: full / design * 100, CycleCount: int(num("CycleCount"))}
			info.Battery = append(info.Battery, b)
		}
	}
	return info, warns, nil
}

func bytesToString[T int8 | uint8](b []T) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return out
}

func collectSmartDarwin(ctx context.Context, _ *State) (any, []string, error) {
	bin := ""
	for _, p := range []string{"/opt/homebrew/bin/smartctl", "/usr/local/bin/smartctl", "/opt/homebrew/sbin/smartctl", "/usr/local/sbin/smartctl"} {
		if fileExists(p) {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, nil, errors.New("smartctl not found - install it with 'brew install smartmontools'")
	}
	disks, version, warns, err := SmartctlDisks(ctx, bin)
	if err != nil {
		return nil, warns, err
	}
	for i := range disks {
		if disks[i].Device == "disk0" || disks[i].Device == "/dev/disk0" {
			disks[i].System = true
		}
	}
	return protocol.SmartData{Source: version, Disks: disks}, warns, nil
}

func collectUpdatesDarwin(ctx context.Context, _ *State) (any, []string, error) {
	u := protocol.UpdatesData{Manager: "softwareupdate", Source: "Apple"}
	out, err := runCmd(ctx, "softwareupdate", "-l")
	if err != nil && !strings.Contains(out, "Software Update Tool") {
		u.SearchError = err.Error()
	}
	re := regexp.MustCompile(`Title: ([^,]+), Version: ([^,]+),.*?Recommended: (\w+)(?:, Action: (\w+))?`)
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		p := protocol.PendingUpdate{Title: strings.TrimSpace(m[1]), Version: strings.TrimSpace(m[2]), Security: strings.Contains(m[1], "Security") || strings.Contains(m[1], "Rapid Security")}
		if m[4] == "restart" {
			p.Category = "requires restart"
		}
		u.Pending = append(u.Pending, p)
	}
	u.PendingCount = len(u.Pending)
	for _, p := range u.Pending {
		if p.Security {
			u.SecurityCount++
		}
	}
	if v, err := runCmd(ctx, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "LastSuccessfulDate"); err == nil {
		if t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(v)); err == nil {
			u.LastSearch = t
		}
	}
	if v, err := runCmd(ctx, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"); err == nil {
		u.AutoUpdates = boolPtr(strings.TrimSpace(v) == "1")
	}
	return u, nil, nil
}

func collectSoftwareDarwin(ctx context.Context, _ *State) (any, []string, error) {
	out, err := runCmd(ctx, "system_profiler", "SPApplicationsDataType", "-json")
	if err != nil {
		return nil, nil, err
	}
	var r struct {
		Apps []struct {
			Name     string `json:"_name"`
			Version  string `json:"version"`
			Obtained string `json:"obtained_from"`
			Path     string `json:"path"`
			Modified string `json:"lastModified"`
			Info     string `json:"info"`
		} `json:"SPApplicationsDataType"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return nil, nil, err
	}
	var items []protocol.SoftwareItem
	for _, a := range r.Apps {
		if strings.HasPrefix(a.Path, "/System/") || strings.HasPrefix(a.Path, "/Library/Apple/") {
			continue
		}
		scope := "machine"
		if strings.HasPrefix(a.Path, "/Users/") {
			scope = "user:" + strings.Split(a.Path, "/")[2]
		}
		it := protocol.SoftwareItem{Name: a.Name, Version: a.Version, Publisher: a.Obtained, Source: "app", Scope: scope}
		if len(a.Modified) >= 10 {
			it.InstallDate = a.Modified[:10]
		}
		items = append(items, it)
	}
	return protocol.SoftwareData{Items: items}, nil, nil
}

func collectAutostartDarwin(ctx context.Context, _ *State) (any, []string, error) {
	var items []protocol.AutostartItem
	globs := map[string]string{"/Library/LaunchDaemons/*.plist": "machine", "/Library/LaunchAgents/*.plist": "machine", "/Users/*/Library/LaunchAgents/*.plist": "user"}
	for g, scope := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			out, err := runCmd(ctx, "plutil", "-convert", "json", "-o", "-", f)
			if err != nil {
				continue
			}
			var p struct {
				Label            string   `json:"Label"`
				Program          string   `json:"Program"`
				ProgramArguments []string `json:"ProgramArguments"`
				Disabled         bool     `json:"Disabled"`
			}
			_ = json.Unmarshal([]byte(out), &p)
			cmd := p.Program
			if len(p.ProgramArguments) > 0 {
				cmd = strings.Join(p.ProgramArguments, " ")
			}
			sc := scope
			if scope == "user" {
				sc = "user:" + strings.Split(f, "/")[2]
			}
			loc := "LaunchAgent"
			if strings.Contains(f, "LaunchDaemons") {
				loc = "LaunchDaemon"
			}
			items = append(items, protocol.AutostartItem{Name: firstNonEmptyStr(p.Label, filepath.Base(f)), Command: cmd, Location: loc + ": " + f, Scope: sc, Enabled: !p.Disabled})
		}
	}
	return protocol.AutostartData{Items: items}, nil, nil
}

func firstNonEmptyStr(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// collectEventsDarwin reports kernel panics (the macOS equivalent of a bluescreen).
func collectEventsDarwin(ctx context.Context, st *State) (any, []string, error) {
	since := st.EventsSince
	if since.IsZero() || time.Since(since) > 31*24*time.Hour {
		since = time.Now().Add(-30 * 24 * time.Hour)
	}
	var evs []protocol.CriticalEvent
	for _, g := range []string{"/Library/Logs/DiagnosticReports/*.panic", "/Library/Logs/DiagnosticReports/Retired/*.panic"} {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			fi, err := os.Stat(f)
			if err != nil || fi.ModTime().Before(since) {
				continue
			}
			evs = append(evs, protocol.CriticalEvent{Kind: protocol.EventBluescreen, Time: fi.ModTime(), Source: "kernel panic", Message: "Kernel panic report " + filepath.Base(f), Key: "panic|" + filepath.Base(f)})
		}
	}
	return protocol.EventsData{Since: since, Events: evs}, nil, nil
}
