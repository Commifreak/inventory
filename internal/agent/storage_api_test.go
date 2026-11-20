package agent

import (
	"testing"

	"github.com/commifreak/inventory/internal/protocol"
)

// NVMe behind Intel RST/VMD: smartctl returns only an error message, the
// storage API fills in what it knows.
func TestFillFromStorageAPI(t *testing.T) {
	d := protocol.Disk{Device: "Disk 0", Protocol: "NVMe", MediaType: "SSD", Bus: "NVMe", System: true,
		Messages: []string{"Read NVMe Identify Controller failed: IOCTL_STORAGE_QUERY_PROPERTY(NVMe) failed, Error=1"}}
	if !smartctlFailed(d) {
		t.Fatal("disk without data not recognised")
	}
	p := msftPhysicalDisk{DeviceId: "0", FriendlyName: "WD PC SN740 SDDQNQD-512G-1016 ", SerialNumber: "E823_8FA6", MediaType: 4, BusType: 8, Size: 512110190592, HealthStatus: 0, FirmwareVersion: "73110000"}
	fillFromStorageAPI(&d, p, &msftReliability{DeviceId: "0", Temperature: 41, Wear: 3, PowerOnHours: 1200, StartStopCycleCount: 300})
	if d.Model != "WD PC SN740 SDDQNQD-512G-1016" || d.Serial != "E823_8FA6" || d.SizeBytes != 512110190592 || d.HealthPassed == nil || !*d.HealthPassed ||
		d.Temperature == nil || *d.Temperature != 41 || d.PercentUsed == nil || *d.PercentUsed != 3 || d.PowerOnHours == nil || *d.PowerOnHours != 1200 {
		t.Errorf("not filled: %+v", d)
	}
	// smartctl values are kept: protocol/bus from smartctl, not "RAID" of the controller.
	if d.Protocol != "NVMe" || d.Bus != "NVMe" || !d.System {
		t.Errorf("smartctl values overwritten: %+v", d)
	}

	ok := protocol.Disk{Model: "Samsung SSD 860 EVO 1TB", HealthPassed: boolPtr(true)}
	if smartctlFailed(ok) {
		t.Error("disk with data treated as failed")
	}
}
