package agent

import (
	"encoding/binary"
	"testing"

	"github.com/commifreak/inventory/internal/protocol"
)

// smbiosBuild assembles one structure: formatted area of length n (header
// included), fields set via set, followed by the string set.
func smbiosBuild(typ byte, handle uint16, n int, set func(b []byte), strs ...string) []byte {
	b := make([]byte, n)
	b[0], b[1] = typ, byte(n)
	binary.LittleEndian.PutUint16(b[2:], handle)
	set(b)
	for _, s := range strs {
		b = append(b, s...)
		b = append(b, 0)
	}
	if len(strs) == 0 {
		b = append(b, 0)
	}
	return append(b, 0)
}

func TestSMBIOSMemoryAndSlots(t *testing.T) {
	le16 := binary.LittleEndian.PutUint16
	le32 := binary.LittleEndian.PutUint32
	var table []byte
	// Type 16: system memory, max 64 GiB (in KB), 4 devices.
	table = append(table, smbiosBuild(16, 0x1000, 0x17, func(b []byte) {
		b[0x05] = 0x03
		le32(b[0x07:], 64<<20)
		le16(b[0x0D:], 4)
	})...)
	// Installed DDR4 SODIMM 16 GiB, 3200 MT/s, configured 2933.
	dimm := func(handle uint16, size uint16, locator string, installed bool) []byte {
		strs := []string{locator, "BANK 0"}
		if installed {
			strs = append(strs, "Samsung", "12345678", "M471A2K43DB1-CWE")
		}
		return smbiosBuild(17, handle, 0x28, func(b []byte) {
			le16(b[0x04:], 0x1000)
			le16(b[0x0C:], size)
			b[0x0E] = 0x0D
			b[0x10], b[0x11] = 1, 2
			if installed {
				b[0x12] = 0x1A
				le16(b[0x15:], 3200)
				b[0x17], b[0x18], b[0x1A] = 3, 4, 5
				le16(b[0x20:], 2933)
			}
		}, strs...)
	}
	table = append(table, dimm(0x1100, 16384, "DIMM A", true)...)
	table = append(table, dimm(0x1101, 0, "DIMM B", false)...)
	// Extended size: 32 GiB via 0x7FFF + extended field.
	table = append(table, smbiosBuild(17, 0x1102, 0x28, func(b []byte) {
		le16(b[0x04:], 0x1000)
		le16(b[0x0C:], 0x7FFF)
		le32(b[0x1C:], 32768)
		b[0x0E] = 0x0B // soldered
		b[0x10] = 1
		b[0x12] = 0x23
	}, "Onboard")...)
	// Memory device of another array (e.g. flash) is ignored.
	table = append(table, smbiosBuild(17, 0x1103, 0x28, func(b []byte) { le16(b[0x04:], 0x2000); le16(b[0x0C:], 64) }, "ROM")...)
	// Slots: M.2 M key in use, PCIe Gen4 x16 available, junk designation.
	table = append(table, smbiosBuild(9, 0x0900, 0x11, func(b []byte) { b[0x04], b[0x05], b[0x06], b[0x07] = 1, 0x17, 0x0A, 0x04 }, "M.2_1")...)
	table = append(table, smbiosBuild(9, 0x0901, 0x11, func(b []byte) { b[0x04], b[0x05], b[0x06], b[0x07] = 1, 0xBD, 0x0D, 0x03 }, "PCIEX16_1")...)
	table = append(table, smbiosBuild(9, 0x0902, 0x11, func(b []byte) { b[0x04], b[0x05], b[0x07] = 1, 0x15, 0x02 }, "To Be Filled By O.E.M.")...)
	table = append(table, smbiosBuild(127, 0xFFFF, 4, func([]byte) {})...)

	var hw protocol.HardwareInfo
	applySMBIOS(&hw, table)
	if hw.MemorySlots != 4 || hw.MemoryMaxBytes != 64<<30 {
		t.Errorf("array: slots=%d max=%d", hw.MemorySlots, hw.MemoryMaxBytes)
	}
	if len(hw.MemoryModules) != 3 {
		t.Fatalf("modules: %+v", hw.MemoryModules)
	}
	a := hw.MemoryModules[0]
	if !a.Installed || a.SizeBytes != 16<<30 || a.Type != "DDR4" || a.FormFactor != "SODIMM" || a.SpeedMTs != 3200 || a.ConfiguredMTs != 2933 ||
		a.Manufacturer != "Samsung" || a.PartNumber != "M471A2K43DB1-CWE" || a.Locator != "DIMM A" || a.Bank != "BANK 0" {
		t.Errorf("dimm A: %+v", a)
	}
	if b := hw.MemoryModules[1]; b.Installed || b.SizeBytes != 0 || b.Locator != "DIMM B" || b.Type != "" {
		t.Errorf("dimm B: %+v", b)
	}
	if c := hw.MemoryModules[2]; !c.Installed || c.SizeBytes != 32<<30 || !c.Soldered || c.Type != "LPDDR5" {
		t.Errorf("onboard: %+v", c)
	}
	if len(hw.Slots) != 3 {
		t.Fatalf("slots: %+v", hw.Slots)
	}
	want := []protocol.SystemSlot{
		{Designation: "M.2_1", Type: "M.2 (M key)", Kind: "storage", Width: "x4", Usage: "in use"},
		{Designation: "PCIEX16_1", Type: "PCIe Gen4 x16", Kind: "expansion", Width: "x16", Usage: "available"},
		{Designation: "slot 3", Type: "M.2 (E key)", Kind: "wireless", Usage: "unknown"},
	}
	for i, w := range want {
		if hw.Slots[i] != w {
			t.Errorf("slot %d: got %+v, want %+v", i, hw.Slots[i], w)
		}
	}
	// Truncated/garbage tables must not panic.
	for i := range table {
		applySMBIOS(&hw, table[:i])
	}
}
