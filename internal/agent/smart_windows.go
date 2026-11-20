package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

type msftPartition struct {
	DiskNumber  uint32
	DriveLetter uint16
}

const storageNS = `root\Microsoft\Windows\Storage`

// driveLettersByDisk maps disk numbers to their drive letters ("C:").
func driveLettersByDisk() map[int][]string {
	var parts []msftPartition
	out := map[int][]string{}
	if err := wmi.QueryNamespace("SELECT DiskNumber, DriveLetter FROM MSFT_Partition", &parts, storageNS); err != nil {
		return out
	}
	for _, p := range parts {
		if p.DriveLetter >= 'A' && p.DriveLetter <= 'Z' {
			out[int(p.DiskNumber)] = append(out[int(p.DiskNumber)], string(rune(p.DriveLetter))+":")
		}
	}
	for n := range out {
		sort.Strings(out[n])
	}
	return out
}

// systemDiskNumber returns the disk number holding the system drive.
func systemDiskNumber() (int, bool) {
	var parts []msftPartition
	letter := strings.ToUpper(envDir("SystemDrive", "C:"))[0]
	if err := wmi.QueryNamespace(fmt.Sprintf("SELECT DiskNumber, DriveLetter FROM MSFT_Partition WHERE DriveLetter=%d", letter), &parts, storageNS); err != nil || len(parts) == 0 {
		return 0, false
	}
	return int(parts[0].DiskNumber), true
}

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
	letters := driveLettersByDisk()

	var relBy map[string]msftReliability // queried when needed
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
					// smartctl names disks like Linux (/dev/sda = PhysicalDrive0);
					// show the Windows disk number as in Disk Management.
					d.Device = fmt.Sprintf("Disk %d", num)
					d.Volumes = letters[num]
					// smartctl could not read the disk (e.g. NVMe behind Intel
					// RST/VMD, whose driver passes no NVMe commands through):
					// take what the Windows storage API knows.
					if p, found := byNumber[num]; found && smartctlFailed(*d) {
						if relBy == nil {
							relBy = reliabilityCounters()
						}
						var r *msftReliability
						if x, ok := relBy[p.DeviceId]; ok {
							r = &x
						}
						fillFromStorageAPI(d, p, r)
						d.Messages = append(d.Messages, storageAPINote)
					}
				}
			}
			return protocol.SmartData{Source: version, Disks: disks}, warns, nil
		}
		if err != nil {
			warns = append(warns, "smartctl: "+err.Error())
		}
	}

	// Fallback: Windows storage reliability counters (less detail).
	relBy = reliabilityCounters()
	var disks []protocol.Disk
	for n, p := range byNumber {
		d := protocol.Disk{Device: fmt.Sprintf("Disk %d", n), Volumes: letters[n], System: sysKnown && n == sysDisk}
		var r *msftReliability
		if x, ok := relBy[p.DeviceId]; ok {
			r = &x
		}
		fillFromStorageAPI(&d, p, r)
		disks = append(disks, d)
	}
	if len(disks) == 0 {
		return nil, warns, fmt.Errorf("no disks found")
	}
	return protocol.SmartData{Source: "Windows storage API (smartctl not available)", Disks: disks}, warns, nil
}

// reliabilityCounters returns MSFT_StorageReliabilityCounter by disk ID.
func reliabilityCounters() map[string]msftReliability {
	var rel []msftReliability
	_ = wmi.QueryNamespace("SELECT DeviceId, Temperature, Wear, ReadErrorsUncorrected, PowerOnHours, StartStopCycleCount FROM MSFT_StorageReliabilityCounter", &rel, storageNS)
	m := map[string]msftReliability{}
	for _, r := range rel {
		m[r.DeviceId] = r
	}
	return m
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
