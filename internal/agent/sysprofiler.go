package agent

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/commifreak/inventory/internal/protocol"
)

// parseSystemProfilerStorage parses "system_profiler SPNVMeDataType
// SPSerialATADataType SPMemoryDataType -json" (macOS). Only occupied ports
// are known.
func parseSystemProfilerStorage(out string, hw *protocol.HardwareInfo) {
	var r map[string][]map[string]any
	if json.Unmarshal([]byte(out), &r) != nil {
		return
	}
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return strings.TrimSpace(v) }
	items := func(m map[string]any) []map[string]any {
		raw, _ := m["_items"].([]any)
		var out []map[string]any
		for _, it := range raw {
			if mm, ok := it.(map[string]any); ok {
				out = append(out, mm)
			}
		}
		return out
	}
	for _, sec := range []struct{ key, typ, speedKey string }{
		{"SPNVMeDataType", "NVMe", "spnvme_linkspeed"},
		{"SPSerialATADataType", "SATA", "spsata_negotiatedlinkspeed"},
	} {
		for _, c := range r[sec.key] {
			sc := protocol.StorageController{Name: str(c, "_name"), Type: sec.typ}
			for _, d := range items(c) {
				p := protocol.StoragePort{Port: strconv.Itoa(len(sc.Ports) + 1), Occupied: true, Device: str(d, "device_model"), Speed: str(d, sec.speedKey)}
				if p.Device == "" {
					p.Device = str(d, "_name")
				}
				if w := str(d, "spnvme_linkwidth"); w != "" && p.Speed != "" {
					p.Speed += " " + w
				}
				if b := str(d, "bsd_name"); b != "" {
					p.Path = "/dev/" + b
				}
				sc.Ports = append(sc.Ports, p)
			}
			if sc.Name != "" {
				hw.StorageControllers = append(hw.StorageControllers, sc)
			}
		}
	}
	for _, m := range r["SPMemoryDataType"] {
		soldered := str(m, "is_memory_upgradeable") == "No"
		mods := items(m)
		if len(mods) == 0 && str(m, "SPMemoryDataType") != "" { // Apple silicon: unified memory
			hw.MemoryModules = append(hw.MemoryModules, protocol.MemoryModule{Locator: "unified memory", Installed: true, Soldered: true,
				SizeBytes: parseSizeGB(str(m, "SPMemoryDataType")), Type: str(m, "dimm_type"), Manufacturer: str(m, "dimm_manufacturer")})
			continue
		}
		for _, d := range mods {
			size := str(d, "dimm_size")
			mm := protocol.MemoryModule{Locator: str(d, "_name"), Soldered: soldered}
			if strings.EqualFold(size, "empty") || strings.EqualFold(str(d, "dimm_status"), "empty") || size == "" {
				hw.MemoryModules = append(hw.MemoryModules, mm)
				continue
			}
			mm.Installed, mm.SizeBytes = true, parseSizeGB(size)
			mm.Type, mm.Manufacturer, mm.PartNumber, mm.Serial = str(d, "dimm_type"), str(d, "dimm_manufacturer"), str(d, "dimm_part_number"), str(d, "dimm_serial_number")
			if f := strings.Fields(str(d, "dimm_speed")); len(f) > 0 {
				mm.SpeedMTs, _ = strconv.Atoi(f[0])
			}
			hw.MemoryModules = append(hw.MemoryModules, mm)
		}
	}
	if n := len(hw.MemoryModules); n > 0 && hw.MemorySlots == 0 {
		hw.MemorySlots = n
	}
}

// parseSizeGB parses "8 GB" / "512 MB".
func parseSizeGB(s string) uint64 {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	switch strings.ToUpper(f[1]) {
	case "TB":
		return uint64(v * (1 << 40))
	case "GB":
		return uint64(v * (1 << 30))
	case "MB":
		return uint64(v * (1 << 20))
	}
	return 0
}
