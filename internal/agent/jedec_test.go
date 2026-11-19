package agent

import "testing"

func TestMemoryVendor(t *testing.T) {
	for in, want := range map[string]string{
		"80CE": "Samsung", "0x80CE": "Samsung", "859B": "Crucial", "80AD": "SK hynix", "0198": "Kingston", "04CD": "G.Skill",
		"CE00000000000000": "Samsung", "7F7F7F7F7F9B0000": "Crucial", "7F98000000000000": "Kingston",
		"Samsung": "Samsung", "Kingston": "Kingston", "1311": "1311", "ABCD": "ABCD", "": "", "7F7F": "7F7F",
	} {
		if got := memoryVendor(in); got != want {
			t.Errorf("memoryVendor(%q) = %q, want %q", in, got, want)
		}
	}
}
