package agent

import (
	"strings"

	"github.com/commifreak/inventory/internal/protocol"
)

// Windows storage API (root/Microsoft/Windows/Storage) classes. The types
// and the mapping live outside the Windows-only files so they can be tested.

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

var busNames = map[uint16]string{1: "SCSI", 3: "ATA", 7: "USB", 8: "RAID", 10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 15: "File", 16: "Storage Spaces", 17: "NVMe"}

// storageAPINote is added to disks whose values come from the storage API
// because smartctl could not read them.
const storageAPINote = "smartctl could not read this disk (its driver passes no SMART commands through, e.g. Intel RST/VMD); values from the Windows storage API, fewer details."

// smartctlFailed reports whether smartctl returned no usable data for a disk.
func smartctlFailed(d protocol.Disk) bool {
	return d.Model == "" && d.Serial == "" && d.HealthPassed == nil && d.Temperature == nil
}

// fillFromStorageAPI sets the values of a disk the storage API provides;
// values already known (from smartctl) are kept.
func fillFromStorageAPI(d *protocol.Disk, p msftPhysicalDisk, r *msftReliability) {
	set := func(dst *string, v string) {
		if *dst == "" {
			*dst = strings.TrimSpace(v)
		}
	}
	set(&d.Model, p.FriendlyName)
	set(&d.Serial, p.SerialNumber)
	set(&d.Firmware, p.FirmwareVersion)
	if d.SizeBytes == 0 {
		d.SizeBytes = p.Size
	}
	if p.BusType == 7 {
		d.External, d.Bus = true, "USB"
	}
	set(&d.Bus, busNames[p.BusType])
	if d.MediaType == "" {
		switch p.MediaType {
		case 3:
			d.MediaType = "HDD"
		case 4:
			d.MediaType = "SSD"
		}
	}
	if p.BusType == 17 {
		set(&d.Protocol, "NVMe")
	}
	if d.HealthPassed == nil {
		switch p.HealthStatus {
		case 0:
			d.HealthPassed = boolPtr(true)
		case 2:
			d.HealthPassed = boolPtr(false)
		}
	}
	if r == nil {
		return
	}
	if d.Temperature == nil && r.Temperature > 0 {
		t := int(r.Temperature)
		d.Temperature = &t
	}
	if d.PercentUsed == nil && (d.Protocol == "NVMe" || r.Wear > 0) {
		w := int(r.Wear)
		d.PercentUsed = &w
	}
	if d.PowerOnHours == nil && r.PowerOnHours > 0 {
		v := int64(r.PowerOnHours)
		d.PowerOnHours = &v
	}
	if d.Uncorrectable == nil {
		v := int64(r.ReadErrorsUncorrected)
		d.Uncorrectable = &v
	}
	if d.PowerCycles == nil && r.StartStopCycleCount > 0 {
		v := int64(r.StartStopCycleCount)
		d.PowerCycles = &v
	}
}
