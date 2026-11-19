package agent

import (
	"strconv"
	"strings"
)

// jedecVendors are common memory vendors by JEP106 bank (1-based) and
// manufacturer code (with parity bit), see JEDEC JEP106.
var jedecVendors = map[[2]int]string{
	{1, 0xCE}: "Samsung", {1, 0x2C}: "Micron", {1, 0xAD}: "SK hynix",
	{2, 0x98}: "Kingston", {2, 0x4F}: "Transcend",
	{3, 0x9E}: "Corsair", {3, 0xFE}: "Elpida",
	{4, 0x0B}: "Nanya",
	{5, 0xCD}: "G.Skill", {5, 0xCB}: "ADATA", {5, 0xEF}: "Team Group", {5, 0x43}: "Ramaxel",
	{6, 0x9B}: "Crucial",
}

// memoryVendor translates JEDEC manufacturer IDs that firmware reports instead
// of names ("80CE", "0x859B", "CE00000000000000", "7F7F7F7F7F9B0000").
// Names and unknown codes are returned unchanged.
func memoryVendor(v string) string {
	s := strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "0x"), "0X"))
	if len(s) < 4 || len(s)%2 != 0 {
		return v
	}
	b := make([]int, len(s)/2)
	for i := range b {
		n, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return v
		}
		b[i] = int(n)
	}
	var bank, code int
	switch {
	case len(b) == 2:
		// DDR4/DDR5 SPD: number of continuation codes (bit 7 = parity), code.
		bank, code = b[0]&0x7F+1, b[1]
	default:
		// DDR2/DDR3: continuation codes 0x7F, then the code, zero padding.
		i := 0
		for i < len(b) && b[i] == 0x7F {
			i++
		}
		if i == len(b) {
			return v
		}
		for _, x := range b[i+1:] {
			if x != 0 {
				return v
			}
		}
		bank, code = i+1, b[i]
	}
	if name, ok := jedecVendors[[2]int{bank, code}]; ok {
		return name
	}
	return v
}
