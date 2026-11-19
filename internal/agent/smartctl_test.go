package agent

import "testing"

func TestSATASSDWear(t *testing.T) {
	attrs := `"ata_smart_attributes":{"table":[{"id":173,"name":"Wear_Leveling_Count","value":92,"worst":92,"thresh":5,"raw":{"value":67,"string":"67"}},
{"id":233,"name":"Media_Wearout_Indicator","value":91,"worst":91,"thresh":0,"raw":{"value":15372123,"string":"15372123"}},
{"id":9,"name":"Power_On_Hours","value":94,"worst":94,"thresh":0,"raw":{"value":29600,"string":"29600"}}]}`
	head := `{"smartctl":{"version":[7,5]},"device":{"name":"/dev/sda","protocol":"ATA"},"model_name":"SAMSUNG MZNTY128HDHP","rotation_rate":0,`
	// Vendor attributes: the worst one counts (233: 91 % left = 9 % used).
	d, err := ParseSmartctl([]byte(head + attrs + `}`))
	if err != nil || d.PercentUsed == nil || *d.PercentUsed != 9 {
		t.Fatalf("vendor attributes: %+v %v", d.PercentUsed, err)
	}
	// The standardised device statistic wins.
	d, _ = ParseSmartctl([]byte(head + attrs + `,"ata_device_statistics":{"pages":[{"number":7,"table":[{"name":"Percentage Used Endurance Indicator","value":4}]}]}}`))
	if d.PercentUsed == nil || *d.PercentUsed != 4 {
		t.Fatalf("device statistics: %+v", d.PercentUsed)
	}
	// Hard disks have no wear.
	d, _ = ParseSmartctl([]byte(`{"device":{"name":"/dev/sdb","protocol":"ATA"},"rotation_rate":5400,` + attrs + `}`))
	if d.PercentUsed != nil {
		t.Fatalf("HDD wear: %d", *d.PercentUsed)
	}
}
