package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yusufpapurcu/wmi"

	"github.com/commifreak/inventory/internal/protocol"
)

// embeddedSmartctl is set by smartctl_embed_windows.go when the build
// includes smartctl.exe (build tag smartctl_embed).
var embeddedSmartctl []byte

// smartctlPath returns a usable smartctl.exe, extracting the embedded copy.
func smartctlPath() string {
	if len(embeddedSmartctl) > 0 {
		dir := filepath.Join(DataDir(), "bin")
		p := filepath.Join(dir, "smartctl.exe")
		if cur, err := os.ReadFile(p); err != nil || !bytes.Equal(cur, embeddedSmartctl) {
			_ = os.MkdirAll(dir, 0o700)
			if err := os.WriteFile(p+".tmp", embeddedSmartctl, 0o755); err == nil {
				_ = os.Remove(p)
				_ = os.Rename(p+".tmp", p)
			}
		}
		if fileExists(p) {
			return p
		}
	}
	exe, _ := os.Executable()
	for _, p := range []string{
		filepath.Join(filepath.Dir(exe), "smartctl.exe"),
		filepath.Join(envDir("ProgramFiles", `C:\Program Files`), `smartmontools\bin\smartctl.exe`),
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

type msftPhysicalDisk struct {
	DeviceId        string
	FriendlyName    string
	SerialNumber    string
	MediaType       uint16
	BusType         uint16
	Size            uint64
	HealthStatus    uint16
	FirmwareVersion string
}

type msftReliability struct {
	DeviceId              string
	Temperature           uint8
	Wear                  uint8
	ReadErrorsUncorrected uint64
	PowerOnHours          uint32
	StartStopCycleCount   uint32
}

type msftPartition struct {
	DiskNumber  uint32
	DriveLetter uint16
}

const storageNS = `root\Microsoft\Windows\Storage`

// systemDiskNumber returns the disk number holding the system drive.
func systemDiskNumber() (int, bool) {
	var parts []msftPartition
	letter := strings.ToUpper(envDir("SystemDrive", "C:"))[0]
	if err := wmi.QueryNamespace(fmt.Sprintf("SELECT DiskNumber, DriveLetter FROM MSFT_Partition WHERE DriveLetter=%d", letter), &parts, storageNS); err != nil || len(parts) == 0 {
		return 0, false
	}
	return int(parts[0].DiskNumber), true
}

var busNames = map[uint16]string{1: "SCSI", 3: "ATA", 7: "USB", 8: "RAID", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 15: "File", 16: "Storage Spaces", 17: "NVMe"}

func collectSmartWindows(ctx context.Context, _ *State) (any, []string, error) {
	var warns []string
	var pdisks []msftPhysicalDisk
	if err := wmi.QueryNamespace("SELECT DeviceId, FriendlyName, SerialNumber, MediaType, BusType, Size, HealthStatus, FirmwareVersion FROM MSFT_PhysicalDisk", &pdisks, storageNS); err != nil {
		warns = append(warns, "storage WMI: "+err.Error())
	}
	byNumber := map[int]msftPhysicalDisk{}
	for _, p := range pdisks {
		if n, err := strconv.Atoi(p.DeviceId); err == nil {
			byNumber[n] = p
		}
	}
	sysDisk, sysKnown := systemDiskNumber()

	if bin := smartctlPath(); bin != "" {
		disks, version, w, err := SmartctlDisks(ctx, bin)
		warns = append(warns, w...)
		if err == nil && len(disks) > 0 {
			for i := range disks {
				d := &disks[i]
				num, ok := windowsDiskNumber(d.Device)
				if !ok {
					// Fall back to matching serial numbers.
					for n, p := range byNumber {
						if d.Serial != "" && strings.EqualFold(strings.TrimSpace(p.SerialNumber), d.Serial) {
							num, ok = n, true
						}
					}
				}
				if ok {
					if p, found := byNumber[num]; found && p.BusType == 7 {
						d.External, d.Bus = true, "USB"
					}
					d.System = sysKnown && num == sysDisk
				}
			}
			return protocol.SmartData{Source: version, Disks: disks}, warns, nil
		}
		if err != nil {
			warns = append(warns, "smartctl: "+err.Error())
		}
	}

	// Fallback: Windows storage reliability counters (less detail).
	var rel []msftReliability
	_ = wmi.QueryNamespace("SELECT DeviceId, Temperature, Wear, ReadErrorsUncorrected, PowerOnHours, StartStopCycleCount FROM MSFT_StorageReliabilityCounter", &rel, storageNS)
	relBy := map[string]msftReliability{}
	for _, r := range rel {
		relBy[r.DeviceId] = r
	}
	var disks []protocol.Disk
	for n, p := range byNumber {
		d := protocol.Disk{Device: fmt.Sprintf(`\\.\PhysicalDrive%d`, n), Model: strings.TrimSpace(p.FriendlyName), Serial: strings.TrimSpace(p.SerialNumber),
			Firmware: p.FirmwareVersion, SizeBytes: p.Size, Bus: busNames[p.BusType], System: sysKnown && n == sysDisk, External: p.BusType == 7}
		switch p.MediaType {
		case 3:
			d.MediaType = "HDD"
		case 4:
			d.MediaType = "SSD"
		}
		if p.BusType == 17 {
			d.Protocol = "NVMe"
		}
		switch p.HealthStatus {
		case 0:
			d.HealthPassed = boolPtr(true)
		case 2:
			d.HealthPassed = boolPtr(false)
		}
		if r, ok := relBy[p.DeviceId]; ok {
			if r.Temperature > 0 {
				t := int(r.Temperature)
				d.Temperature = &t
			}
			if d.Protocol == "NVMe" || r.Wear > 0 {
				w := int(r.Wear)
				d.PercentUsed = &w
			}
			poh, unc, cyc := int64(r.PowerOnHours), int64(r.ReadErrorsUncorrected), int64(r.StartStopCycleCount)
			if poh > 0 {
				d.PowerOnHours = &poh
			}
			d.Uncorrectable = &unc
			if cyc > 0 {
				d.PowerCycles = &cyc
			}
		}
		disks = append(disks, d)
	}
	if len(disks) == 0 {
		return nil, warns, fmt.Errorf("no disks found")
	}
	return protocol.SmartData{Source: "Windows storage API (smartctl not available)", Disks: disks}, warns, nil
}

// windowsDiskNumber maps smartctl device names (/dev/sda = PhysicalDrive0) to disk numbers.
func windowsDiskNumber(dev string) (int, bool) {
	name := strings.TrimPrefix(dev, "/dev/")
	if strings.HasPrefix(name, "sd") && len(name) >= 3 {
		n := 0
		for _, c := range name[2:] {
			if c < 'a' || c > 'z' {
				return 0, false
			}
			n = n*26 + int(c-'a') + 1
		}
		return n - 1, true
	}
	if rest, ok := strings.CutPrefix(strings.ToLower(name), "pd"); ok {
		n, err := strconv.Atoi(rest)
		return n, err == nil
	}
	return 0, false
}
