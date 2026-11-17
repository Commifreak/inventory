package agent

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unsafe"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"

	"github.com/commifreak/inventory/internal/protocol"
)

var pciVenRe = regexp.MustCompile(`^PCI\\VEN_([0-9A-F]{4})`)

var (
	procGetSystemFirmwareTable = modkernel32.NewProc("GetSystemFirmwareTable")
	modcfgmgr32                = windows.NewLazySystemDLL("cfgmgr32.dll")
	procCMLocateDevNodeW       = modcfgmgr32.NewProc("CM_Locate_DevNodeW")
	procCMGetParent            = modcfgmgr32.NewProc("CM_Get_Parent")
	procCMGetDeviceIDW         = modcfgmgr32.NewProc("CM_Get_Device_IDW")
)

// windowsSMBIOS returns the raw SMBIOS structure table.
func windowsSMBIOS() ([]byte, error) {
	const rsmb = 0x52534D42 // 'RSMB'
	n, _, err := procGetSystemFirmwareTable.Call(rsmb, 0, 0, 0)
	if n == 0 {
		return nil, err
	}
	buf := make([]byte, n)
	r, _, err := procGetSystemFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buf[0])), n)
	if r == 0 || r > n {
		return nil, err
	}
	// RawSMBIOSData: 4 version bytes, DWORD length, table.
	if len(buf) < 8 {
		return nil, fmt.Errorf("short SMBIOS data")
	}
	l := int(uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24)
	if 8+l > len(buf) {
		l = len(buf) - 8
	}
	return buf[8 : 8+l], nil
}

type win32PnPController struct {
	Name         string
	PNPClass     string
	Manufacturer string
	DeviceID     string
	Service      string
	CompatibleID []string
}

type win32StorageDevice struct {
	Model           string
	Name            string
	PNPDeviceID     string
	DeviceID        string
	Drive           string
	SCSIBus         uint32
	SCSITargetId    uint16
	SCSILogicalUnit uint16
}

// windowsStorageControllers lists hardware storage controllers (PnP classes
// HDC and SCSIAdapter, PCI and VMBus) with the disks and optical drives attached to them. The
// controller type comes from the PCI class code (language independent).
// Empty ports cannot be determined, except that an NVMe controller always
// holds exactly one SSD.
func windowsStorageControllers() ([]protocol.StorageController, error) {
	var ctrls []win32PnPController
	if err := wmi.Query("SELECT Name, PNPClass, Manufacturer, DeviceID, Service, CompatibleID FROM Win32_PnPEntity WHERE PNPClass='HDC' OR PNPClass='SCSIAdapter'", &ctrls); err != nil {
		return nil, err
	}
	var disks, cds []win32StorageDevice
	_ = wmi.Query("SELECT Model, PNPDeviceID, DeviceID, SCSIBus, SCSITargetId, SCSILogicalUnit FROM Win32_DiskDrive", &disks)
	_ = wmi.Query("SELECT Name, PNPDeviceID, Drive, SCSIBus, SCSITargetId, SCSILogicalUnit FROM Win32_CDROMDrive", &cds)

	var out []protocol.StorageController
	index := map[string]int{}
	for _, c := range ctrls {
		id := strings.ToUpper(c.DeviceID)
		if strings.HasPrefix(id, `ROOT\`) || strings.HasPrefix(id, `SWD\`) {
			continue // software adapters: Storage Spaces, iSCSI initiator, ...
		}
		sc := protocol.StorageController{Name: strings.TrimSpace(c.Name), Vendor: strings.TrimSpace(c.Manufacturer), Driver: c.Service,
			Location: c.DeviceID, Type: windowsStorageType(c.CompatibleID)}
		// The PnP manufacturer is often the driver's ("Standard NVM Express
		// Controller", localized); prefer the vendor from the PCI ID.
		if m := pciVenRe.FindStringSubmatch(id); m != nil {
			if v := pciVendorFallback[strings.ToLower(m[1])]; v != "" {
				sc.Vendor = v
			}
		}
		if sc.Vendor == sc.Name {
			sc.Vendor = ""
		}
		if sc.Type == "storage" { // no PCI class code, e.g. Hyper-V (VMBus)
			sc.Type = map[string]string{"SCSIADAPTER": "SCSI", "HDC": "IDE/ATA"}[strings.ToUpper(c.PNPClass)]
		}
		index[strings.ToUpper(c.DeviceID)] = len(out)
		out = append(out, sc)
	}
	attach := func(d win32StorageDevice, model, path string) {
		id := d.PNPDeviceID
		for range 4 { // the controller is usually the direct parent
			parent := cmParent(id)
			if parent == "" {
				return
			}
			if i, ok := index[strings.ToUpper(parent)]; ok {
				port := fmt.Sprintf("bus %d · target %d", d.SCSIBus, d.SCSITargetId)
				if d.SCSILogicalUnit != 0 {
					port += fmt.Sprintf(" · LUN %d", d.SCSILogicalUnit)
				}
				out[i].Ports = append(out[i].Ports, protocol.StoragePort{Port: port,
					Occupied: true, Device: strings.TrimSpace(model), Path: path})
				return
			}
			id = parent
		}
	}
	for _, d := range disks {
		attach(d, d.Model, d.DeviceID)
	}
	for _, d := range cds {
		attach(d, d.Name, d.Drive)
	}
	for i := range out {
		slices.SortFunc(out[i].Ports, func(a, b protocol.StoragePort) int { return strings.Compare(a.Port, b.Port) })
		if out[i].Type == "NVMe" {
			if len(out[i].Ports) == 0 {
				out[i].Ports = []protocol.StoragePort{{Port: "1", Occupied: true}}
			}
			out[i].Ports[0].Port = "1"
			out[i].PortsComplete = len(out[i].Ports) == 1
		}
	}
	return out, nil
}

// windowsStorageType maps the PCI class code from the compatible IDs
// ("PCI\CC_010601") to a controller type.
func windowsStorageType(compat []string) string {
	for _, id := range compat {
		u := strings.ToUpper(id)
		i := strings.Index(u, "CC_01")
		if i < 0 {
			continue
		}
		cc := u[i+3:]
		switch {
		case strings.HasPrefix(cc, "010802"):
			return "NVMe"
		case strings.HasPrefix(cc, "010601"):
			return "SATA (AHCI)"
		case strings.HasPrefix(cc, "0106"):
			return "SATA"
		case strings.HasPrefix(cc, "0104"):
			return "RAID"
		case strings.HasPrefix(cc, "0107"):
			return "SAS"
		case strings.HasPrefix(cc, "0101"):
			return "IDE"
		case strings.HasPrefix(cc, "0105"):
			return "ATA"
		case strings.HasPrefix(cc, "0100"):
			return "SCSI"
		case strings.HasPrefix(cc, "0108"):
			return "NVM"
		}
	}
	return "storage"
}

// cmParent returns the device instance ID of a device's parent.
func cmParent(deviceID string) string {
	id, err := windows.UTF16PtrFromString(deviceID)
	if err != nil {
		return ""
	}
	var inst, parent uint32
	if r, _, _ := procCMLocateDevNodeW.Call(uintptr(unsafe.Pointer(&inst)), uintptr(unsafe.Pointer(id)), 0); r != 0 {
		return ""
	}
	if r, _, _ := procCMGetParent.Call(uintptr(unsafe.Pointer(&parent)), uintptr(inst), 0); r != 0 {
		return ""
	}
	buf := make([]uint16, 512)
	if r, _, _ := procCMGetDeviceIDW.Call(uintptr(parent), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0); r != 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}
