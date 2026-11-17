package agent

import (
	"testing"

	"github.com/commifreak/inventory/internal/protocol"
)

func TestParseSystemProfilerStorage(t *testing.T) {
	intel := `{
  "SPNVMeDataType": [{"_name": "Generic SSD Controller", "_items": [{"_name": "APPLE SSD AP0512M", "bsd_name": "disk0", "device_model": "APPLE SSD AP0512M", "spnvme_linkspeed": "8.0 GT/s", "spnvme_linkwidth": "x4"}]}],
  "SPSerialATADataType": [{"_name": "Intel 8 Series Chipset", "_items": [{"_name": "WDC WD10EZEX", "bsd_name": "disk1", "device_model": "WDC WD10EZEX", "spsata_negotiatedlinkspeed": "6 Gigabit"}]}],
  "SPMemoryDataType": [{"_name": "memory", "is_memory_upgradeable": "Yes", "_items": [
    {"_name": "DIMM0/BANK 0", "dimm_size": "8 GB", "dimm_speed": "2667 MHz", "dimm_status": "ok", "dimm_type": "DDR4", "dimm_manufacturer": "0x80CE", "dimm_part_number": "M471A1K43CB1-CTD"},
    {"_name": "DIMM0/BANK 1", "dimm_size": "empty", "dimm_status": "empty"}]}]
}`
	var hw protocol.HardwareInfo
	parseSystemProfilerStorage(intel, &hw)
	if len(hw.StorageControllers) != 2 {
		t.Fatalf("controllers: %+v", hw.StorageControllers)
	}
	if p := hw.StorageControllers[0].Ports[0]; hw.StorageControllers[0].Type != "NVMe" || p.Path != "/dev/disk0" || p.Speed != "8.0 GT/s x4" || p.Device != "APPLE SSD AP0512M" {
		t.Errorf("nvme: %+v", hw.StorageControllers[0])
	}
	if p := hw.StorageControllers[1].Ports[0]; hw.StorageControllers[1].Type != "SATA" || p.Speed != "6 Gigabit" || hw.StorageControllers[1].PortsComplete {
		t.Errorf("sata: %+v", hw.StorageControllers[1])
	}
	if hw.MemorySlots != 2 || len(hw.MemoryModules) != 2 {
		t.Fatalf("memory: %+v", hw.MemoryModules)
	}
	if m := hw.MemoryModules[0]; !m.Installed || m.SizeBytes != 8<<30 || m.SpeedMTs != 2667 || m.Type != "DDR4" || m.Soldered {
		t.Errorf("dimm 0: %+v", m)
	}
	if m := hw.MemoryModules[1]; m.Installed {
		t.Errorf("dimm 1 must be empty: %+v", m)
	}

	appleSilicon := `{"SPNVMeDataType": [], "SPSerialATADataType": [], "SPMemoryDataType": [{"_name": "Memory", "SPMemoryDataType": "16 GB", "dimm_manufacturer": "Hynix", "dimm_type": "LPDDR5"}]}`
	hw = protocol.HardwareInfo{}
	parseSystemProfilerStorage(appleSilicon, &hw)
	if len(hw.MemoryModules) != 1 || !hw.MemoryModules[0].Soldered || hw.MemoryModules[0].SizeBytes != 16<<30 || hw.MemoryModules[0].Type != "LPDDR5" {
		t.Errorf("apple silicon memory: %+v", hw.MemoryModules)
	}
}
