package agent

import (
	"context"
	"fmt"
	"math/bits"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	"github.com/commifreak/inventory/internal/protocol"
)

func platformCollectors() map[string]Collector {
	return map[string]Collector{
		protocol.CollectSystem:    collectSystemWindows,
		protocol.CollectSMART:     collectSmartWindows,
		protocol.CollectUpdates:   collectUpdatesWindows,
		protocol.CollectSoftware:  collectSoftwareWindows,
		protocol.CollectAutostart: collectAutostartWindows,
		protocol.CollectEvents:    collectEventsWindows,
	}
}

func platformAfterUpdate() { updateUninstallVersion() }

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

func regDWord(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return v, true
}

type win32ComputerSystemProduct struct{ UUID string }

// Identity identifies this machine.
func Identity() protocol.Identity {
	h, _ := os.Hostname()
	id := protocol.Identity{Hostname: h, OS: protocol.OSWindows, Arch: runtime.GOARCH,
		MachineID: regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, "MachineGuid")}
	var p []win32ComputerSystemProduct
	if err := wmi.Query("SELECT UUID FROM Win32_ComputerSystemProduct", &p); err == nil && len(p) > 0 {
		id.HardwareID = strings.ToUpper(cleanID(p[0].UUID))
	}
	return id
}

// BootTime returns the system boot time.
func BootTime() time.Time {
	return time.Now().Add(-time.Duration(tickCount64()) * time.Millisecond).Truncate(time.Second)
}

// ---------------------------------------------------------------------------
// system
// ---------------------------------------------------------------------------

type win32ComputerSystem struct {
	Manufacturer        string
	Model               string
	TotalPhysicalMemory uint64
	UserName            string
	HypervisorPresent   bool
}

type win32BIOS struct {
	Manufacturer      string
	SMBIOSBIOSVersion string
	SerialNumber      string
	ReleaseDate       time.Time
}

type win32BaseBoard struct {
	Manufacturer string
	Product      string
}

type win32Processor struct {
	Name                      string
	NumberOfCores             uint32
	NumberOfLogicalProcessors uint32
}

type win32LogicalDisk struct {
	DeviceID   string
	FileSystem string
	Size       uint64
	FreeSpace  uint64
	VolumeName string
}

type win32NetAdapterConfig struct {
	Index                uint32
	Description          string
	MACAddress           string
	IPAddress            []string
	IPSubnet             []string
	DefaultIPGateway     []string
	DNSServerSearchOrder []string
	DHCPEnabled          bool
}

type win32NetAdapter struct {
	Index               uint32
	NetConnectionID     string
	NetConnectionStatus uint16
}

type win32EncryptableVolume struct {
	DriveLetter      string
	ProtectionStatus uint32
	ConversionStatus uint32
}

type win32Tpm struct {
	IsEnabled_InitialValue bool
	SpecVersion            string
}

type msftMpComputerStatus struct {
	AMServiceEnabled              bool
	AntivirusEnabled              bool
	RealTimeProtectionEnabled     bool
	AMRunningMode                 string
	AntivirusSignatureLastUpdated time.Time
	AntivirusSignatureAge         uint32
	AntivirusSignatureVersion     string
	QuickScanEndTime              time.Time
	IsTamperProtected             bool
}

type softwareLicensingProduct struct {
	Name              string
	LicenseStatus     uint32
	ProductKeyChannel string
}

type batteryStatic struct {
	InstanceName     string
	DesignedCapacity uint32
	DeviceName       string
}

type batteryFull struct {
	InstanceName        string
	FullChargedCapacity uint32
}

type batteryCycle struct {
	InstanceName string
	CycleCount   uint32
}

func collectSystemWindows(ctx context.Context, _ *State) (any, []string, error) {
	var warns []string
	warn := func(what string, err error) {
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s: %v", what, err))
		}
	}
	info := protocol.SystemInfo{}

	// Operating system (registry is fast and language independent).
	const cv = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	name := regString(registry.LOCAL_MACHINE, cv, "ProductName")
	build := regString(registry.LOCAL_MACHINE, cv, "CurrentBuild")
	ubr, _ := regDWord(registry.LOCAL_MACHINE, cv, "UBR")
	buildNum, _ := strconv.Atoi(build)
	if buildNum >= 22000 {
		// The registry still says "Windows 10" on Windows 11.
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	major, _ := regDWord(registry.LOCAL_MACHINE, cv, "CurrentMajorVersionNumber")
	minor, _ := regDWord(registry.LOCAL_MACHINE, cv, "CurrentMinorVersionNumber")
	dv := regString(registry.LOCAL_MACHINE, cv, "DisplayVersion")
	if dv == "" {
		dv = regString(registry.LOCAL_MACHINE, cv, "ReleaseId")
	}
	info.OS = protocol.OSInfo{
		Family:         protocol.OSWindows,
		Name:           name,
		Version:        fmt.Sprintf("%d.%d.%s.%d", major, minor, build, ubr),
		Build:          fmt.Sprintf("%s.%d", build, ubr),
		DisplayVersion: dv,
		Edition:        regString(registry.LOCAL_MACHINE, cv, "EditionID"),
		Arch:           runtime.GOARCH,
		BootTime:       BootTime(),
		Timezone:       regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, "TimeZoneKeyName"),
	}
	if inst, ok := regDWord(registry.LOCAL_MACHINE, cv, "InstallDate"); ok && inst > 0 {
		info.OS.InstallDate = time.Unix(int64(inst), 0)
	}

	// Hardware
	var cs []win32ComputerSystem
	warn("computer system", wmi.Query("SELECT Manufacturer, Model, TotalPhysicalMemory, UserName, HypervisorPresent FROM Win32_ComputerSystem", &cs))
	var bios []win32BIOS
	warn("bios", wmi.Query("SELECT Manufacturer, SMBIOSBIOSVersion, SerialNumber, ReleaseDate FROM Win32_BIOS", &bios))
	var board []win32BaseBoard
	_ = wmi.Query("SELECT Manufacturer, Product FROM Win32_BaseBoard", &board)
	var cpus []win32Processor
	warn("processor", wmi.Query("SELECT Name, NumberOfCores, NumberOfLogicalProcessors FROM Win32_Processor", &cpus))
	id := Identity()
	hw := protocol.HardwareInfo{UUID: id.HardwareID}
	if len(cs) > 0 {
		hw.Manufacturer, hw.Model, hw.MemoryBytes = strings.TrimSpace(cs[0].Manufacturer), strings.TrimSpace(cs[0].Model), cs[0].TotalPhysicalMemory
		m := strings.ToLower(cs[0].Manufacturer + " " + cs[0].Model)
		for _, v := range []string{"virtual", "vmware", "qemu", "kvm", "xen", "virtualbox", "parallels", "bochs"} {
			if strings.Contains(m, v) {
				hw.Virtual = true
			}
		}
		if cs[0].UserName != "" {
			info.Users.CurrentUsers = []string{cs[0].UserName + " (Console)"}
		}
	}
	if len(bios) > 0 {
		hw.SerialNumber = cleanID(bios[0].SerialNumber)
		hw.BIOSVendor, hw.BIOSVersion = bios[0].Manufacturer, bios[0].SMBIOSBIOSVersion
		if !bios[0].ReleaseDate.IsZero() {
			hw.BIOSDate = bios[0].ReleaseDate.Format("2006-01-02")
		}
	}
	if len(board) > 0 {
		hw.Board = strings.TrimSpace(board[0].Manufacturer + " " + board[0].Product)
	}
	for _, c := range cpus {
		hw.CPU = strings.TrimSpace(c.Name)
		hw.CPUCores += int(c.NumberOfCores)
		hw.CPUThreads += int(c.NumberOfLogicalProcessors)
	}
	if table, err := windowsSMBIOS(); err == nil {
		applySMBIOS(&hw, table) // memory slots/modules, expansion slots
	} else {
		warn("smbios", err)
	}
	ctrls, err := windowsStorageControllers()
	warn("storage controllers", err)
	hw.StorageControllers = ctrls
	info.Hardware = hw

	// Volumes and BitLocker
	var disks []win32LogicalDisk
	warn("volumes", wmi.Query("SELECT DeviceID, FileSystem, Size, FreeSpace, VolumeName FROM Win32_LogicalDisk WHERE DriveType=3", &disks))
	var bl []win32EncryptableVolume
	blErr := wmi.QueryNamespace("SELECT DriveLetter, ProtectionStatus, ConversionStatus FROM Win32_EncryptableVolume", &bl, `root\CIMV2\Security\MicrosoftVolumeEncryption`)
	blByDrive := map[string]win32EncryptableVolume{}
	for _, v := range bl {
		blByDrive[strings.ToUpper(v.DriveLetter)] = v
	}
	sysDrive := strings.ToUpper(envDir("SystemDrive", "C:"))
	for _, d := range disks {
		v := protocol.Volume{Mount: d.DeviceID, Label: d.VolumeName, FS: d.FileSystem, SizeBytes: d.Size, FreeBytes: d.FreeSpace, System: strings.EqualFold(d.DeviceID, sysDrive)}
		if e, ok := blByDrive[strings.ToUpper(d.DeviceID)]; ok {
			enc := e.ConversionStatus == 1 || e.ConversionStatus == 2 || e.ConversionStatus == 4
			v.Encrypted = boolPtr(enc)
			switch {
			case e.ProtectionStatus == 1:
				v.Encryption = "BitLocker on"
			case enc:
				v.Encryption = "BitLocker suspended"
			default:
				v.Encryption = "BitLocker off"
			}
		} else if blErr == nil && v.System {
			v.Encrypted = boolPtr(false)
			v.Encryption = "BitLocker off"
		}
		info.Volumes = append(info.Volumes, v)
	}

	// Network
	var cfgs []win32NetAdapterConfig
	warn("network", wmi.Query("SELECT Index, Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE", &cfgs))
	var adapters []win32NetAdapter
	_ = wmi.Query("SELECT Index, NetConnectionID, NetConnectionStatus FROM Win32_NetworkAdapter WHERE NetConnectionID IS NOT NULL", &adapters)
	byIndex := map[uint32]win32NetAdapter{}
	for _, a := range adapters {
		byIndex[a.Index] = a
	}
	for _, c := range cfgs {
		a := protocol.NetAdapter{Name: c.Description, Description: c.Description, MAC: c.MACAddress, Gateways: c.DefaultIPGateway, DNS: c.DNSServerSearchOrder, DHCP: boolPtr(c.DHCPEnabled), Up: true}
		if na, ok := byIndex[c.Index]; ok {
			a.Name = na.NetConnectionID
			a.Up = na.NetConnectionStatus == 2
		}
		for i, ip := range c.IPAddress {
			if i < len(c.IPSubnet) {
				ip += "/" + subnetBits(c.IPSubnet[i])
			}
			a.IPs = append(a.IPs, ip)
		}
		low := strings.ToLower(a.Name + " " + c.Description)
		a.Wireless = strings.Contains(low, "wi-fi") || strings.Contains(low, "wlan") || strings.Contains(low, "wireless") || strings.Contains(low, "802.11")
		info.Gateways = append(info.Gateways, c.DefaultIPGateway...)
		info.DNS = append(info.DNS, c.DNSServerSearchOrder...)
		info.Network = append(info.Network, a)
	}
	info.Gateways, info.DNS = uniqueStrings(info.Gateways), uniqueStrings(info.DNS)
	if out, err := runCmd(ctx, "netsh", "wlan", "show", "interfaces"); err == nil {
		re := regexp.MustCompile(`(?m)^\s*SSID\s*:\s*(.+?)\s*$`)
		if m := re.FindStringSubmatch(out); m != nil {
			info.WiFiSSID = m[1]
		}
	}

	// Users: all sessions (console, RDP, disconnected) via the WTS API.
	if sessions, err := windowsSessions(); err == nil {
		info.Users.CurrentUsers = sessions
	} else {
		warn("sessions", err)
	}
	info.Users.LastLogons = windowsLastLogons()
	adminGroup := sidName("S-1-5-32-544")
	if i := strings.LastIndex(adminGroup, `\`); i >= 0 {
		adminGroup = adminGroup[i+1:]
	}
	info.Users.AdminGroup = adminGroup
	members, err := localGroupMembers(adminGroup)
	warn("administrators", err)
	info.Users.Admins = members

	// Security
	info.Security.SecureBoot = windowsSecureBoot()
	var mp []msftMpComputerStatus
	if err := wmi.QueryNamespace("SELECT * FROM MSFT_MpComputerStatus", &mp, `root\Microsoft\Windows\Defender`); err == nil && len(mp) > 0 {
		m := mp[0]
		info.Security.Defender = &protocol.DefenderInfo{Present: true, ServiceEnabled: m.AMServiceEnabled, AntivirusEnabled: m.AntivirusEnabled,
			RealTimeProtection: m.RealTimeProtectionEnabled, RunningMode: m.AMRunningMode, SignatureUpdated: m.AntivirusSignatureLastUpdated,
			SignatureAgeDays: int(m.AntivirusSignatureAge), SignatureVersion: m.AntivirusSignatureVersion, LastQuickScan: m.QuickScanEndTime,
			TamperProtection: boolPtr(m.IsTamperProtected)}
		if m.AMRunningMode == "" && !m.AMServiceEnabled {
			info.Security.Defender.RunningMode = "Disabled"
		}
		if dets, err := defenderDetections(); err == nil {
			info.Security.Defender.Detections = dets
		} else {
			warn("defender detections", err)
		}
		if ex, err := defenderExclusions(); err == nil {
			info.Security.Defender.Exclusions = ex
		} else {
			warn("defender exclusions", err)
		}
	} else {
		info.Security.Defender = &protocol.DefenderInfo{Present: false}
	}
	if av, err := windowsAntivirus(); err == nil {
		info.Security.Antivirus = av
	} else {
		warn("security center", err)
	}
	if fw, err := windowsFirewall(); err == nil {
		info.Security.Firewall = fw
	} else {
		warn("firewall", err)
	}
	var lic []softwareLicensingProduct
	if err := wmi.Query("SELECT Name, LicenseStatus, ProductKeyChannel FROM SoftwareLicensingProduct WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL", &lic); err == nil && len(lic) > 0 {
		names := []string{"Unlicensed", "Licensed", "OOB grace", "OOT grace", "Non-genuine grace", "Notification", "Extended grace"}
		st := "Unknown"
		if int(lic[0].LicenseStatus) < len(names) {
			st = names[lic[0].LicenseStatus]
		}
		info.Security.Activation = &protocol.ActivationInfo{Licensed: lic[0].LicenseStatus == 1, Status: st, Product: lic[0].Name, Channel: lic[0].ProductKeyChannel}
	} else {
		warn("activation", err)
	}
	var tpm []win32Tpm
	if err := wmi.QueryNamespace("SELECT IsEnabled_InitialValue, SpecVersion FROM Win32_Tpm", &tpm, `root\CIMV2\Security\MicrosoftTpm`); err == nil {
		if len(tpm) > 0 {
			info.Security.TPM = &protocol.TPMInfo{Present: true, Version: strings.TrimSpace(strings.SplitN(tpm[0].SpecVersion, ",", 2)[0])}
		} else {
			info.Security.TPM = &protocol.TPMInfo{Present: false}
		}
	}

	// Battery
	var bs []batteryStatic
	if wmi.QueryNamespace("SELECT InstanceName, DesignedCapacity, DeviceName FROM BatteryStaticData", &bs, `root\WMI`) == nil && len(bs) > 0 {
		var bf []batteryFull
		var bc []batteryCycle
		_ = wmi.QueryNamespace("SELECT InstanceName, FullChargedCapacity FROM BatteryFullChargedCapacity", &bf, `root\WMI`)
		_ = wmi.QueryNamespace("SELECT InstanceName, CycleCount FROM BatteryCycleCount", &bc, `root\WMI`)
		for _, b := range bs {
			bat := protocol.Battery{Name: strings.TrimSpace(b.DeviceName), DesignCapacity: float64(b.DesignedCapacity)}
			for _, f := range bf {
				if f.InstanceName == b.InstanceName {
					bat.FullChargeCapacity = float64(f.FullChargedCapacity)
				}
			}
			for _, c := range bc {
				if c.InstanceName == b.InstanceName {
					bat.CycleCount = int(c.CycleCount)
				}
			}
			if bat.DesignCapacity > 0 {
				bat.HealthPercent = bat.FullChargeCapacity / bat.DesignCapacity * 100
				info.Battery = append(info.Battery, bat)
			}
		}
	}
	return info, warns, nil
}

func subnetBits(mask string) string {
	if !strings.Contains(mask, ".") {
		return mask // IPv6 prefix length
	}
	n := 0
	for _, p := range strings.Split(mask, ".") {
		v, _ := strconv.Atoi(p)
		n += bits.OnesCount8(uint8(v))
	}
	return strconv.Itoa(n)
}

// windowsLastLogons uses the profile load time from the ProfileList.
func windowsLastLogons() []protocol.UserLogon {
	const pl = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, pl, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer k.Close()
	sids, _ := k.ReadSubKeyNames(-1)
	var out []protocol.UserLogon
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasPrefix(sid, "S-1-12-1-") { // local/domain or Entra ID users
			continue
		}
		hi, ok1 := regDWord(registry.LOCAL_MACHINE, pl+`\`+sid, "LocalProfileLoadTimeHigh")
		lo, ok2 := regDWord(registry.LOCAL_MACHINE, pl+`\`+sid, "LocalProfileLoadTimeLow")
		var t time.Time
		if ok1 && ok2 {
			ft := hi<<32 | lo
			t = time.Unix(0, int64(ft-116444736000000000)*100)
		}
		name := sidName(sid)
		if name == sid {
			if p := regString(registry.LOCAL_MACHINE, pl+`\`+sid, "ProfileImagePath"); p != "" {
				name = p[strings.LastIndex(p, `\`)+1:]
			}
		}
		out = append(out, protocol.UserLogon{User: name, Time: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

func windowsSecureBoot() *protocol.SecureBootInfo {
	sb := &protocol.SecureBootInfo{}
	v, ok := regDWord(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled")
	if !ok {
		return sb // legacy BIOS
	}
	sb.Supported = true
	sb.Enabled = v == 1
	sb.ServicingStatus = regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing`, "UEFICA2023Status")
	if err := enablePrivilege("SeSystemEnvironmentPrivilege"); err != nil {
		sb.Error = "cannot read UEFI variables: " + err.Error()
		return sb
	}
	db, err := firmwareVar("db", "{"+efiImgDB+"}")
	if err != nil {
		sb.Error = "reading UEFI db: " + err.Error()
	}
	kek, _ := firmwareVar("KEK", "{"+efiGlobal+"}")
	applySecureBootCerts(sb, db, kek)
	return sb
}

const (
	efiGlobal = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	efiImgDB  = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
)
