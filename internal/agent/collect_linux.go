package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
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
		protocol.CollectSystem:    collectSystemLinux,
		protocol.CollectSMART:     collectSmartLinux,
		protocol.CollectUpdates:   collectUpdatesLinux,
		protocol.CollectSoftware:  collectSoftwareLinux,
		protocol.CollectAutostart: collectAutostartLinux,
		protocol.CollectEvents:    collectEventsLinux,
	}
}

// Identity identifies this machine.
func Identity() protocol.Identity {
	h, _ := os.Hostname()
	return protocol.Identity{
		Hostname:   h,
		OS:         protocol.OSLinux,
		Arch:       runtime.GOARCH,
		HardwareID: strings.ToUpper(cleanID(readTrim("/sys/class/dmi/id/product_uuid"))),
		MachineID:  readTrim("/etc/machine-id"),
	}
}

// BootTime returns the system boot time.
func BootTime() time.Time {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return time.Unix(n, 0)
		}
	}
	return time.Time{}
}

func parseKV(path string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(strings.TrimSpace(k), "#") {
			continue
		}
		m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return m
}

// ---------------------------------------------------------------------------
// system
// ---------------------------------------------------------------------------

func collectSystemLinux(ctx context.Context, _ *State) (any, []string, error) {
	var warns []string
	info := protocol.SystemInfo{}

	osr := parseKV("/etc/os-release")
	if len(osr) == 0 {
		osr = parseKV("/usr/lib/os-release")
	}
	var uts syscall.Utsname
	_ = syscall.Uname(&uts)
	info.OS = protocol.OSInfo{
		Family:        protocol.OSLinux,
		Name:          firstNonEmpty(osr["PRETTY_NAME"], osr["NAME"], "Linux"),
		Version:       firstNonEmpty(osr["VERSION_ID"], osr["BUILD_ID"]),
		DistroID:      osr["ID"],
		DistroVersion: osr["VERSION_ID"],
		Codename:      osr["VERSION_CODENAME"],
		Kernel:        readTrim("/proc/sys/kernel/osrelease"),
		Arch:          runtime.GOARCH,
		BootTime:      BootTime(),
	}
	if tz, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(tz, "zoneinfo/"); i >= 0 {
			info.OS.Timezone = tz[i+9:]
		}
	} else if tz := readTrim("/etc/timezone"); tz != "" {
		info.OS.Timezone = tz
	}

	// Hardware
	hw := protocol.HardwareInfo{
		Manufacturer: readTrim("/sys/class/dmi/id/sys_vendor"),
		Model:        readTrim("/sys/class/dmi/id/product_name"),
		SerialNumber: cleanID(readTrim("/sys/class/dmi/id/product_serial")),
		UUID:         cleanID(readTrim("/sys/class/dmi/id/product_uuid")),
		BIOSVendor:   readTrim("/sys/class/dmi/id/bios_vendor"),
		BIOSVersion:  readTrim("/sys/class/dmi/id/bios_version"),
		BIOSDate:     readTrim("/sys/class/dmi/id/bios_date"),
		Board:        strings.TrimSpace(readTrim("/sys/class/dmi/id/board_vendor") + " " + readTrim("/sys/class/dmi/id/board_name")),
		CPUThreads:   runtime.NumCPU(),
	}
	if m := readTrim("/proc/device-tree/model"); m != "" && hw.Model == "" {
		hw.Model = m // Raspberry Pi and other boards
	}
	cpu, cores, serial := parseCPUInfo()
	hw.CPU, hw.CPUCores = cpu, cores
	if hw.SerialNumber == "" {
		hw.SerialNumber = cleanID(serial)
	}
	if hw.CPUCores == 0 {
		hw.CPUCores = hw.CPUThreads
	}
	if mem := parseKVColon("/proc/meminfo")["MemTotal"]; mem != "" {
		kb, _ := strconv.ParseUint(strings.Fields(mem)[0], 10, 64)
		hw.MemoryBytes = kb * 1024
	}
	if out, err := runCmd(ctx, "systemd-detect-virt"); err == nil {
		v := strings.TrimSpace(out)
		hw.Virtual = v != "" && v != "none"
	}
	info.Hardware = hw

	blk := lsblk(ctx)
	info.Volumes = linuxVolumes(blk)
	info.Network, info.Gateways = linuxNetwork()
	info.DNS = linuxDNS(ctx)
	if out, err := runCmd(ctx, "iwgetid", "-r"); err == nil {
		info.WiFiSSID = strings.TrimSpace(out)
	} else if out, err := runCmd(ctx, "nmcli", "-t", "-f", "active,ssid", "dev", "wifi"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if s, ok := strings.CutPrefix(l, "yes:"); ok {
				info.WiFiSSID = s
				break
			}
		}
	}

	u, w := linuxUsers(ctx)
	info.Users = u
	warns = append(warns, w...)
	info.Security.SecureBoot = linuxSecureBoot()
	if fileExists("/sys/class/tpm/tpm0") {
		v := readTrim("/sys/class/tpm/tpm0/tpm_version_major")
		if v != "" {
			v += ".0"
		}
		info.Security.TPM = &protocol.TPMInfo{Present: true, Version: v}
	} else {
		info.Security.TPM = &protocol.TPMInfo{Present: false}
	}
	info.Battery = linuxBatteries()
	info.PiPower = piPower(ctx, "/sys/class/hwmon")
	return info, warns, nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseKVColon(path string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func parseCPUInfo() (model string, cores int, serial string) {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return
	}
	type pc struct{ phys, core string }
	seen := map[pc]bool{}
	var phys string
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "model name", "Model", "Hardware", "cpu model":
			if model == "" || k == "model name" {
				model = v
			}
		case "physical id":
			phys = v
		case "core id":
			seen[pc{phys, v}] = true
		case "Serial":
			serial = v
		}
	}
	cores = len(seen)
	return
}

// lsblkDev is a node of "lsblk -J" output.
type lsblkDev struct {
	Name       string     `json:"name"`
	Path       string     `json:"path"`
	Type       string     `json:"type"`
	FSType     string     `json:"fstype"`
	Mountpoint string     `json:"mountpoint"`
	Serial     string     `json:"serial"`
	Tran       string     `json:"tran"`
	Model      string     `json:"model"`
	RM         any        `json:"rm"` // bool or "0"/"1" depending on version
	Children   []lsblkDev `json:"children"`
}

func lsblk(ctx context.Context) []lsblkDev {
	out, err := runCmd(ctx, "lsblk", "-J", "-o", "NAME,PATH,TYPE,FSTYPE,MOUNTPOINT,SERIAL,TRAN,MODEL,RM")
	if err != nil {
		return nil
	}
	var r struct {
		Blockdevices []lsblkDev `json:"blockdevices"`
	}
	_ = json.Unmarshal([]byte(out), &r)
	return r.Blockdevices
}

// walkBlk calls fn for every node with its top-level disk and whether an
// encryption layer lies between them.
func walkBlk(devs []lsblkDev, fn func(node, disk lsblkDev, crypt bool)) {
	var rec func(n, disk lsblkDev, crypt bool)
	rec = func(n, disk lsblkDev, crypt bool) {
		if n.Type == "crypt" {
			crypt = true
		}
		fn(n, disk, crypt)
		for _, c := range n.Children {
			rec(c, disk, crypt)
		}
	}
	for _, d := range devs {
		rec(d, d, false)
	}
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"ntfs": true, "ntfs3": true, "exfat": true, "vfat": true, "jfs": true, "reiserfs": true, "bcachefs": true, "fuseblk": true}

func linuxVolumes(blk []lsblkDev) []protocol.Volume {
	crypt := map[string]bool{}
	walkBlk(blk, func(n, _ lsblkDev, c bool) {
		if n.Mountpoint != "" {
			crypt[n.Mountpoint] = c
		}
	})
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return nil
	}
	defer f.Close()
	var vols []protocol.Volume
	seenDev := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		dev, mnt, fstype := fields[0], unescapeMount(fields[1]), fields[2]
		if !realFS[fstype] || strings.HasPrefix(mnt, "/snap/") || strings.HasPrefix(mnt, "/var/lib/docker") || strings.HasPrefix(mnt, "/run/") {
			continue
		}
		if seenDev[dev] && fstype != "btrfs" {
			continue
		}
		if fstype == "btrfs" && seenDev[dev] {
			continue // btrfs subvolumes share the same space
		}
		seenDev[dev] = true
		var st syscall.Statfs_t
		if err := syscall.Statfs(mnt, &st); err != nil {
			continue
		}
		v := protocol.Volume{Mount: mnt, FS: fstype, Device: dev, SizeBytes: st.Blocks * uint64(st.Bsize), FreeBytes: st.Bavail * uint64(st.Bsize), System: mnt == "/"}
		if c, ok := crypt[mnt]; ok {
			v.Encrypted = boolPtr(c)
			if c {
				v.Encryption = "LUKS"
			} else if mnt == "/" {
				v.Encryption = "none"
			}
		}
		vols = append(vols, v)
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].Mount < vols[j].Mount })
	return vols
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

func skipIface(name string) bool {
	for _, p := range []string{"lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "vnet", "tap"} {
		if name == p || (p != "lo" && strings.HasPrefix(name, p)) {
			return true
		}
	}
	return false
}

func linuxNetwork() ([]protocol.NetAdapter, []string) {
	gwByIface := map[string][]string{}
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, l := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(l)
			if len(f) > 2 && f[1] == "00000000" {
				if gw, err := strconv.ParseUint(f[2], 16, 32); err == nil && gw != 0 {
					ip := net.IPv4(byte(gw), byte(gw>>8), byte(gw>>16), byte(gw>>24))
					gwByIface[f[0]] = append(gwByIface[f[0]], ip.String())
				}
			}
		}
	}
	if b, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Fields(l)
			if len(f) >= 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[4] != strings.Repeat("0", 32) {
				if raw, err := hexIP(f[4]); err == nil {
					gwByIface[f[9]] = append(gwByIface[f[9]], raw.String())
				}
			}
		}
	}
	ifaces, _ := net.Interfaces()
	var out []protocol.NetAdapter
	var gws []string
	for _, ifc := range ifaces {
		if skipIface(ifc.Name) || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		a := protocol.NetAdapter{Name: ifc.Name, MAC: ifc.HardwareAddr.String(), Up: ifc.Flags&net.FlagUp != 0,
			Wireless: fileExists("/sys/class/net/" + ifc.Name + "/wireless"), Gateways: uniqueStrings(gwByIface[ifc.Name])}
		if addrs, err := ifc.Addrs(); err == nil {
			for _, ad := range addrs {
				a.IPs = append(a.IPs, ad.String())
			}
		}
		if len(a.IPs) == 0 && !a.Up {
			continue
		}
		if drv, err := os.Readlink("/sys/class/net/" + ifc.Name + "/device/driver"); err == nil {
			a.Description = filepath.Base(drv)
		}
		gws = append(gws, a.Gateways...)
		out = append(out, a)
	}
	return out, uniqueStrings(gws)
}

func hexIP(s string) (net.IP, error) {
	if len(s) != 32 {
		return nil, fmt.Errorf("bad ipv6")
	}
	ip := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		ip[i] = byte(v)
	}
	return ip, nil
}

func linuxDNS(ctx context.Context) []string {
	var dns []string
	b, _ := os.ReadFile("/etc/resolv.conf")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" {
			dns = append(dns, f[1])
		}
	}
	// systemd-resolved stub: ask resolvectl for the real servers.
	if len(dns) == 1 && strings.HasPrefix(dns[0], "127.0.0.") && hasCmd("resolvectl") {
		if out, err := runCmd(ctx, "resolvectl", "dns"); err == nil {
			var real []string
			for _, l := range strings.Split(out, "\n") {
				_, v, ok := strings.Cut(l, ":")
				if ok {
					real = append(real, strings.Fields(v)...)
				}
			}
			if len(real) > 0 {
				dns = real
			}
		}
	}
	return uniqueStrings(dns)
}

var lastDateRe = regexp.MustCompile(`\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +(\d{1,2}) (\d\d:\d\d:\d\d) (\d{4})\b`)

func linuxUsers(ctx context.Context) (protocol.UsersInfo, []string) {
	var u protocol.UsersInfo
	var warns []string
	if out, err := runCmd(ctx, "who"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) > 0 {
				u.CurrentUsers = append(u.CurrentUsers, f[0])
			}
		}
		u.CurrentUsers = uniqueStrings(u.CurrentUsers)
	}
	out, err := runCmd(ctx, "last", "-F", "-w", "-n", "200")
	if err != nil && hasCmd("wtmpdb") {
		out, err = runCmd(ctx, "wtmpdb", "last", "-F", "-n", "200")
	}
	if err == nil {
		latest := map[string]protocol.UserLogon{}
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) < 3 || f[0] == "reboot" || f[0] == "wtmp" || f[0] == "wtmpdb" || f[0] == "shutdown" {
				continue
			}
			m := lastDateRe.FindStringSubmatchIndex(l)
			if m == nil {
				continue
			}
			t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(strings.Fields(l[m[0]:m[1]]), " "), time.Local)
			if err != nil {
				continue
			}
			pre := strings.Fields(l[:m[0]])
			from := ""
			if len(pre) >= 3 && !strings.HasPrefix(pre[2], ":") {
				from = pre[2]
			}
			if cur, ok := latest[f[0]]; !ok || t.After(cur.Time) {
				latest[f[0]] = protocol.UserLogon{User: f[0], Time: t, From: from}
			}
		}
		for _, v := range latest {
			u.LastLogons = append(u.LastLogons, v)
		}
		sort.Slice(u.LastLogons, func(i, j int) bool { return u.LastLogons[i].Time.After(u.LastLogons[j].Time) })
	} else {
		warns = append(warns, "last logons: "+err.Error())
	}
	var groups []string
	for _, g := range []string{"sudo", "wheel", "admin"} {
		grp, err := user.LookupGroup(g)
		if err != nil {
			continue
		}
		groups = append(groups, g)
		u.Admins = append(u.Admins, groupMembers(grp.Gid)...)
	}
	u.Admins = uniqueStrings(append([]string{"root"}, u.Admins...))
	u.AdminGroup = "root, " + strings.Join(groups, ", ")
	return u, warns
}

// groupMembers lists explicit members and users with that primary group.
func groupMembers(gid string) []string {
	var out []string
	if b, err := os.ReadFile("/etc/group"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) == 4 && f[2] == gid && f[3] != "" {
				out = append(out, strings.Split(f[3], ",")...)
			}
		}
	}
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) >= 4 && f[3] == gid {
				out = append(out, f[0])
			}
		}
	}
	return out
}

const (
	efiGlobal = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	efiImgDB  = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
)

func linuxSecureBoot() *protocol.SecureBootInfo {
	sb := &protocol.SecureBootInfo{}
	vars := "/sys/firmware/efi/efivars/"
	v, err := os.ReadFile(vars + "SecureBoot-" + efiGlobal)
	if err != nil || len(v) < 5 {
		return sb // no UEFI or no Secure Boot variables
	}
	sb.Supported = true
	sb.Enabled = v[4] == 1
	db, _ := os.ReadFile(vars + "db-" + efiImgDB)
	kek, _ := os.ReadFile(vars + "KEK-" + efiGlobal)
	applySecureBootCerts(sb, db, kek)
	return sb
}

func linuxBatteries() []protocol.Battery {
	var out []protocol.Battery
	matches, _ := filepath.Glob("/sys/class/power_supply/*")
	for _, p := range matches {
		if readTrim(p+"/type") != "Battery" || readTrim(p+"/scope") == "Device" {
			continue
		}
		num := func(name string) float64 {
			v, _ := strconv.ParseFloat(readTrim(p+"/"+name), 64)
			return v
		}
		full, design := num("energy_full")/1000, num("energy_full_design")/1000 // µWh -> mWh
		if design == 0 {
			volt := num("voltage_min_design") / 1e6
			full, design = num("charge_full")/1000*volt, num("charge_full_design")/1000*volt
		}
		if design == 0 {
			continue
		}
		b := protocol.Battery{Name: filepath.Base(p), DesignCapacity: design, FullChargeCapacity: full, HealthPercent: full / design * 100,
			CycleCount: int(num("cycle_count")), Status: readTrim(p + "/status")}
		if m := readTrim(p + "/model_name"); m != "" {
			b.Name += " (" + m + ")"
		}
		out = append(out, b)
	}
	return out
}

// ---------------------------------------------------------------------------
// smart
// ---------------------------------------------------------------------------

func collectSmartLinux(ctx context.Context, _ *State) (any, []string, error) {
	var sysSerial, sysPath string
	usb := map[string]bool{}
	walkBlk(lsblk(ctx), func(n, disk lsblkDev, _ bool) {
		if n.Mountpoint == "/" {
			sysSerial, sysPath = disk.Serial, disk.Path
		}
		if disk.Tran == "usb" {
			usb[disk.Path] = true
			if disk.Serial != "" {
				usb[disk.Serial] = true
			}
		}
	})
	// SD cards and eMMC have no SMART; list them so they are visible, with
	// eMMC wear data where available. Their errors come from the kernel log.
	mmc := mmcDisks("/sys/block", sysPath)

	bin := "smartctl"
	if !hasCmd(bin) {
		for _, p := range []string{"/usr/sbin/smartctl", "/sbin/smartctl", "/usr/local/sbin/smartctl"} {
			if fileExists(p) {
				bin = p
			}
		}
	}
	if !hasCmd(bin) && !fileExists(bin) {
		if len(mmc) > 0 {
			return protocol.SmartData{Source: "sysfs (smartctl not installed)", Disks: mmc},
				[]string{"smartctl not found - install smartmontools for USB/SATA/NVMe disks"}, nil
		}
		return nil, nil, fmt.Errorf("smartctl not found - install the smartmontools package")
	}
	disks, version, warns, err := SmartctlDisks(ctx, bin)
	if err != nil {
		if len(mmc) > 0 {
			return protocol.SmartData{Source: "sysfs", Disks: mmc}, append(warns, "smartctl: "+err.Error()), nil
		}
		return nil, warns, err
	}
	for i := range disks {
		d := &disks[i]
		if (sysSerial != "" && strings.EqualFold(d.Serial, sysSerial)) || (sysPath != "" && strings.HasPrefix(sysPath, d.Device)) {
			d.System = true
		}
		if usb[d.Device] || (d.Serial != "" && usb[d.Serial]) {
			d.External, d.Bus = true, "USB"
		}
	}
	disks = append(disks, mmc...)
	return protocol.SmartData{Source: version, Disks: disks}, warns, nil
}

var mmcNameRe = regexp.MustCompile(`^mmcblk\d+$`)

// mmcDisks describes SD cards and eMMC devices from sysfs.
func mmcDisks(sysBlock, sysPath string) []protocol.Disk {
	entries, _ := os.ReadDir(sysBlock)
	var out []protocol.Disk
	for _, e := range entries {
		name := e.Name()
		if !mmcNameRe.MatchString(name) {
			continue
		}
		dev := filepath.Join(sysBlock, name, "device")
		typ := readTrim(filepath.Join(dev, "type")) // "SD" or "MMC"
		d := protocol.Disk{Device: "/dev/" + name, Model: readTrim(filepath.Join(dev, "name")), Serial: readTrim(filepath.Join(dev, "serial")),
			Protocol: typ, MediaType: "Flash", Bus: typ, System: sysPath == "/dev/"+name}
		if typ == "MMC" {
			d.Bus = "eMMC"
		}
		if d.Serial != "" && d.Model != "" {
			d.Serial = d.Model + "-" + d.Serial // card serials are only unique per vendor
		}
		if sectors, err := strconv.ParseUint(readTrim(filepath.Join(sysBlock, name, "size")), 10, 64); err == nil {
			d.SizeBytes = sectors * 512
		}
		if date := readTrim(filepath.Join(dev, "date")); date != "" {
			d.Firmware = "manufactured " + date
		}
		// eMMC 5.0+: life_time "0xA 0xB" (estimates in 10% steps, 0x0B = exceeded), pre_eol_info.
		if lt := strings.Fields(readTrim(filepath.Join(dev, "life_time"))); len(lt) > 0 {
			max := 0
			for _, v := range lt {
				if n, err := strconv.ParseInt(strings.TrimPrefix(v, "0x"), 16, 64); err == nil && int(n) > max {
					max = int(n)
				}
			}
			if max > 0 {
				used := max * 10
				d.PercentUsed = &used
			}
		}
		switch readTrim(filepath.Join(dev, "pre_eol_info")) {
		case "0x02", "0x2":
			d.Messages = append(d.Messages, "eMMC reserved blocks: warning (80% consumed)")
		case "0x03", "0x3":
			d.Messages = append(d.Messages, "eMMC reserved blocks: urgent (90% consumed)")
			d.HealthPassed = boolPtr(false)
		}
		out = append(out, d)
	}
	return out
}

// piPower reads the Raspberry Pi throttling state: "vcgencmd get_throttled"
// if available, otherwise the rpi_volt hwmon alarm (current state only).
func piPower(ctx context.Context, hwmonDir string) *protocol.PiPowerInfo {
	if hasCmd("vcgencmd") {
		if out, err := runCmd(ctx, "vcgencmd", "get_throttled"); err == nil {
			if p := parseThrottled(out); p != nil {
				return p
			}
		}
	}
	dirs, _ := filepath.Glob(filepath.Join(hwmonDir, "hwmon*"))
	for _, d := range dirs {
		if readTrim(filepath.Join(d, "name")) == "rpi_volt" {
			return &protocol.PiPowerInfo{Source: "hwmon", UndervoltageNow: readTrim(filepath.Join(d, "in0_lcrit_alarm")) == "1"}
		}
	}
	return nil
}

// parseThrottled decodes "throttled=0x50005".
func parseThrottled(out string) *protocol.PiPowerInfo {
	_, v, ok := strings.Cut(strings.TrimSpace(out), "=")
	if !ok {
		return nil
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(v), "0x"), 16, 32)
	if err != nil {
		return nil
	}
	bit := func(i uint) bool { return n&(1<<i) != 0 }
	return &protocol.PiPowerInfo{Source: "vcgencmd", Raw: v,
		UndervoltageNow: bit(0), FreqCappedNow: bit(1), ThrottledNow: bit(2), SoftTempLimitNow: bit(3),
		UndervoltageSinceBoot: bit(16), FreqCappedSinceBoot: bit(17), ThrottledSinceBoot: bit(18), SoftTempLimitSinceBoot: bit(19)}
}
