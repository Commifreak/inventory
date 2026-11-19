package agent

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"

	"github.com/commifreak/inventory/internal/protocol"
)

// SMBIOS parsing (raw structure table: Windows GetSystemFirmwareTable("RSMB"),
// Linux /sys/firmware/dmi/tables/DMI). Used structure types:
//   16 Physical Memory Array, 17 Memory Device, 9 System Slots.

type smbiosStruct struct {
	typ     byte
	handle  uint16
	data    []byte // formatted area incl. header
	strings []string
}

func (s smbiosStruct) byteAt(off int) (byte, bool) {
	if off < len(s.data) {
		return s.data[off], true
	}
	return 0, false
}

func (s smbiosStruct) word(off int) (uint16, bool) {
	if off+2 <= len(s.data) {
		return binary.LittleEndian.Uint16(s.data[off:]), true
	}
	return 0, false
}

func (s smbiosStruct) dword(off int) (uint32, bool) {
	if off+4 <= len(s.data) {
		return binary.LittleEndian.Uint32(s.data[off:]), true
	}
	return 0, false
}

func (s smbiosStruct) qword(off int) (uint64, bool) {
	if off+8 <= len(s.data) {
		return binary.LittleEndian.Uint64(s.data[off:]), true
	}
	return 0, false
}

// str returns the string referenced at offset off (1-based string index).
func (s smbiosStruct) str(off int) string {
	i, ok := s.byteAt(off)
	if !ok || i == 0 || int(i) > len(s.strings) {
		return ""
	}
	return cleanSMBIOSString(s.strings[i-1])
}

// cleanSMBIOSString drops placeholders vendors put into empty fields.
func cleanSMBIOSString(v string) string {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "", "not specified", "unknown", "none", "[empty]", "no dimm", "undefined", "n/a", "na", "empty",
		"to be filled by o.e.m.", "default string", "manufacturer00", "partnum0", "sernum0", "00000000", "0000000000000000":
		return ""
	}
	return v
}

// parseSMBIOSTable splits a raw table into structures.
func parseSMBIOSTable(b []byte) []smbiosStruct {
	var out []smbiosStruct
	for len(b) >= 4 {
		typ, l := b[0], int(b[1])
		if l < 4 || l > len(b) {
			break
		}
		s := smbiosStruct{typ: typ, handle: binary.LittleEndian.Uint16(b[2:]), data: b[:l]}
		rest := b[l:]
		// String set: NUL-terminated strings, ended by an extra NUL.
		end := -1
		for i := 0; i+1 < len(rest); i++ {
			if rest[i] == 0 && rest[i+1] == 0 {
				end = i
				break
			}
		}
		if end < 0 {
			break
		}
		if end > 0 {
			s.strings = strings.Split(string(rest[:end]), "\x00")
		}
		out = append(out, s)
		if typ == 127 { // end of table
			break
		}
		b = rest[end+2:]
	}
	return out
}

var smbiosMemoryTypes = map[byte]string{0x0F: "SDRAM", 0x12: "DDR", 0x13: "DDR2", 0x14: "DDR2 FB-DIMM", 0x18: "DDR3", 0x19: "FBD2",
	0x1A: "DDR4", 0x1B: "LPDDR", 0x1C: "LPDDR2", 0x1D: "LPDDR3", 0x1E: "LPDDR4", 0x20: "HBM", 0x21: "HBM2", 0x22: "DDR5",
	0x23: "LPDDR5", 0x24: "HBM3"}

var smbiosFormFactors = map[byte]string{0x03: "SIMM", 0x05: "chip", 0x08: "proprietary card", 0x09: "DIMM", 0x0A: "TSOP",
	0x0B: "row of chips", 0x0C: "RIMM", 0x0D: "SODIMM", 0x0F: "FB-DIMM", 0x10: "die", 0x11: "CAMM"}

// smbiosMemory returns slot count, maximum capacity and the memory devices of
// the system memory arrays.
func smbiosMemory(structs []smbiosStruct) (slots int, maxBytes uint64, modules []protocol.MemoryModule) {
	arrays := map[uint16]bool{}
	for _, s := range structs {
		if s.typ != 16 {
			continue
		}
		if use, _ := s.byteAt(0x05); use != 0x03 { // system memory only
			continue
		}
		arrays[s.handle] = true
		if n, ok := s.word(0x0D); ok {
			slots += int(n)
		}
		if kb, ok := s.dword(0x07); ok {
			if kb == 0x80000000 {
				if ext, ok := s.qword(0x0F); ok {
					maxBytes += ext
				}
			} else {
				maxBytes += uint64(kb) * 1024
			}
		}
	}
	for _, s := range structs {
		if s.typ != 17 {
			continue
		}
		if h, ok := s.word(0x04); ok && len(arrays) > 0 && !arrays[h] {
			continue
		}
		m := protocol.MemoryModule{Locator: s.str(0x10), Bank: s.str(0x11)}
		if size, ok := s.word(0x0C); ok {
			switch {
			case size == 0:
			case size == 0xFFFF:
				m.Installed = true // size unknown
			case size == 0x7FFF:
				if ext, ok := s.dword(0x1C); ok {
					m.SizeBytes = uint64(ext&0x7FFFFFFF) << 20
				}
				m.Installed = true
			case size&0x8000 != 0:
				m.SizeBytes = uint64(size&0x7FFF) << 10
				m.Installed = true
			default:
				m.SizeBytes = uint64(size) << 20
				m.Installed = true
			}
		}
		ff, _ := s.byteAt(0x0E)
		m.FormFactor = smbiosFormFactors[ff]
		m.Soldered = ff == 0x05 || ff == 0x0A || ff == 0x0B || ff == 0x10
		if m.Installed {
			if t, ok := s.byteAt(0x12); ok {
				m.Type = smbiosMemoryTypes[t]
			}
			m.SpeedMTs = smbiosSpeed(s, 0x15, 0x54)
			m.ConfiguredMTs = smbiosSpeed(s, 0x20, 0x58)
			m.Manufacturer = memoryVendor(s.str(0x17))
			m.Serial = s.str(0x18)
			m.PartNumber = s.str(0x1A)
		}
		if m.Locator == "" {
			m.Locator = fmt.Sprintf("slot %d", len(modules)+1)
		}
		modules = append(modules, m)
	}
	if slots < len(modules) {
		slots = len(modules)
	}
	return slots, maxBytes, modules
}

func smbiosSpeed(s smbiosStruct, off, extOff int) int {
	v, ok := s.word(off)
	if !ok || v == 0 {
		return 0
	}
	if v == 0xFFFF {
		if ext, ok := s.dword(extOff); ok {
			return int(ext & 0x7FFFFFFF)
		}
		return 0
	}
	return int(v)
}

var smbiosSlotWidths = map[byte]string{0x08: "x1", 0x09: "x2", 0x0A: "x4", 0x0B: "x8", 0x0C: "x12", 0x0D: "x16", 0x0E: "x32"}

// smbiosSlotType names a slot type and classifies it.
func smbiosSlotType(t byte) (name, kind string) {
	pcieWidths := []string{"x1", "x2", "x4", "x8", "x16"}
	gen := func(base byte, g string) (string, bool) {
		if t == base {
			return "PCIe " + g, true
		}
		if t > base && t <= base+5 {
			return "PCIe " + g + " " + pcieWidths[t-base-1], true
		}
		return "", false
	}
	switch t {
	case 0x06:
		return "PCI", "expansion"
	case 0x0E:
		return "PCI 66 MHz", "expansion"
	case 0x0F, 0x10, 0x11, 0x13:
		return "AGP", "expansion"
	case 0x12:
		return "PCI-X", "expansion"
	case 0x14:
		return "M.2 (A key)", "wireless"
	case 0x15:
		return "M.2 (E key)", "wireless"
	case 0x16:
		return "M.2 (B key)", "storage"
	case 0x17:
		return "M.2 (M key)", "storage"
	case 0x1F, 0x20, 0x24, 0x25:
		return "U.2", "storage"
	case 0x21, 0x22, 0x23:
		return "PCIe Mini Card", "wireless"
	case 0xA5:
		return "PCIe", "expansion"
	case 0xC4:
		return "PCIe Gen6", "expansion"
	case 0xC5, 0xC6:
		return "EDSFF", "storage"
	}
	if t >= 0xA6 && t <= 0xAA {
		return "PCIe " + pcieWidths[t-0xA6], "expansion"
	}
	for _, g := range []struct {
		base byte
		name string
	}{{0xAB, "Gen2"}, {0xB1, "Gen3"}, {0xB8, "Gen4"}, {0xBE, "Gen5"}} {
		if n, ok := gen(g.base, g.name); ok {
			return n, "expansion"
		}
	}
	return fmt.Sprintf("type 0x%02X", t), "other"
}

var (
	m2Name     = regexp.MustCompile(`(?i)(^|[^A-Z0-9])M\.?2([^0-9]|$)|NGFF`) // "M.2 SSD1", "M.2_1", "M2_1"
	m2Storage  = regexp.MustCompile(`(?i)SSD|NVME|STORAGE|SATA|DISK`)
	m2Wireless = regexp.MustCompile(`(?i)WLAN|WIFI|WI-FI|WWAN|LTE|5G|BT\b|BLUETOOTH|KEY ?[AE]\b`)
)

// classifyM2Slot handles vendors (e.g. HP) that describe M.2 slots with a
// PCIe slot type: the designation ("M.2 SSD1", "M.2 WLAN/BT") tells what the
// slot is for.
func classifyM2Slot(sl protocol.SystemSlot) (typ, kind string) {
	typ, kind = sl.Type, sl.Kind
	if !m2Name.MatchString(sl.Designation) {
		return typ, kind
	}
	if !strings.HasPrefix(typ, "M.2") && !strings.HasPrefix(typ, "U.2") {
		typ = "M.2 · " + typ
	}
	switch {
	case m2Storage.MatchString(sl.Designation):
		kind = "storage"
	case m2Wireless.MatchString(sl.Designation):
		kind = "wireless"
	case kind == "expansion" && sl.Width == "x4":
		kind = "storage" // x4 M.2 slots are SSD slots
	}
	return typ, kind
}

func smbiosSlots(structs []smbiosStruct) []protocol.SystemSlot {
	var out []protocol.SystemSlot
	for _, s := range structs {
		if s.typ != 9 {
			continue
		}
		t, ok := s.byteAt(0x05)
		if !ok {
			continue
		}
		name, kind := smbiosSlotType(t)
		sl := protocol.SystemSlot{Designation: s.str(0x04), Type: name, Kind: kind, Usage: "unknown"}
		if w, ok := s.byteAt(0x06); ok {
			sl.Width = smbiosSlotWidths[w]
		}
		sl.Type, sl.Kind = classifyM2Slot(sl)
		switch u, _ := s.byteAt(0x07); u {
		case 0x03:
			sl.Usage = "available"
		case 0x04:
			sl.Usage = "in use"
		case 0x05:
			sl.Usage = "unavailable"
		}
		if sl.Designation == "" {
			sl.Designation = fmt.Sprintf("slot %d", len(out)+1)
		}
		out = append(out, sl)
	}
	return out
}

// applySMBIOS fills memory and slot information from a raw SMBIOS table.
func applySMBIOS(hw *protocol.HardwareInfo, table []byte) {
	structs := parseSMBIOSTable(table)
	hw.MemorySlots, hw.MemoryMaxBytes, hw.MemoryModules = smbiosMemory(structs)
	hw.Slots = smbiosSlots(structs)
}
