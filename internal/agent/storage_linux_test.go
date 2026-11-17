package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxStorageControllers(t *testing.T) {
	sys := t.TempDir()
	w := func(rel, content string) {
		p := filepath.Join(sys, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, rel string) {
		p := filepath.Join(sys, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.MkdirAll(filepath.Join(sys, target), 0o755)
		if err := os.Symlink(filepath.Join(sys, target), p); err != nil {
			t.Fatal(err)
		}
	}
	// AHCI controller with 4 ports: port 1 disk (6 Gbps), port 2 empty, port 3 DVD, port 4 empty.
	ahci := "bus/pci/devices/0000:00:17.0"
	w(ahci+"/class", "0x010601")
	w(ahci+"/vendor", "0x8086")
	w(ahci+"/device", "0xa352")
	link("bus/pci/drivers/ahci", ahci+"/driver")
	for i, spd := range []string{"6.0 Gbps", "<unknown>", "1.5 Gbps", "<unknown>"} {
		n := string(rune('1' + i))
		w(ahci+"/ata"+n+"/link"+n+"/ata_link/link"+n+"/sata_spd", spd)
	}
	w(ahci+"/ata1/link1/dev1.0/ata_device/dev1.0/class", "ata")
	_ = os.MkdirAll(filepath.Join(sys, ahci, "ata1/host0/target0:0:0/0:0:0:0/block/sda"), 0o755)
	w("block/sda/device/vendor", "ATA")
	w("block/sda/device/model", "Samsung SSD 870")
	_ = os.MkdirAll(filepath.Join(sys, ahci, "ata3/host2/target2:0:0/2:0:0:0/block/sr0"), 0o755)
	w("block/sr0/device/vendor", "HL-DT-ST")
	w("block/sr0/device/model", "DVDRAM GUD1N")
	// NVMe controller.
	nvme := "bus/pci/devices/0000:01:00.0"
	w(nvme+"/class", "0x010802")
	w(nvme+"/vendor", "0x144d")
	w(nvme+"/device", "0xa80a")
	w(nvme+"/current_link_speed", "16.0 GT/s PCIe")
	w(nvme+"/current_link_width", "4")
	w(nvme+"/nvme/nvme0/model", "Samsung SSD 980 PRO 1TB")
	_ = os.MkdirAll(filepath.Join(sys, nvme, "nvme/nvme0/nvme0n1"), 0o755)
	// Network card (not storage) is ignored.
	w("bus/pci/devices/0000:02:00.0/class", "0x020000")
	// SD card host with a card, SDIO host with Wi-Fi.
	link("devices/platform/fe340000.mmc", "class/mmc_host/mmc0/device")
	link("bus/platform/drivers/sdhci-iproc", "devices/platform/fe340000.mmc/driver")
	w("class/mmc_host/mmc0/mmc0:aaaa/type", "SD")
	w("class/mmc_host/mmc0/mmc0:aaaa/name", "SC32G")
	_ = os.MkdirAll(filepath.Join(sys, "class/mmc_host/mmc0/mmc0:aaaa/block/mmcblk0"), 0o755)
	w("class/mmc_host/mmc1/mmc1:0001/type", "SDIO")
	_ = os.MkdirAll(filepath.Join(sys, "class/mmc_host/mmc2"), 0o755) // empty slot

	cs := linuxStorageControllers(sys)
	if len(cs) != 5 {
		t.Fatalf("expected 5 controllers, got %d: %+v", len(cs), cs)
	}
	a := cs[0]
	if a.Type != "SATA (AHCI)" || a.Driver != "ahci" || a.Vendor != "Intel" || !a.PortsComplete || len(a.Ports) != 4 || a.Name != "Intel SATA (AHCI) controller [8086:a352]" {
		t.Fatalf("ahci: %+v", a)
	}
	if p := a.Ports[0]; !p.Occupied || p.Speed != "6.0 Gbps" || p.Path != "/dev/sda" || p.Device != "Samsung SSD 870" {
		t.Errorf("port 1: %+v", p)
	}
	if p := a.Ports[1]; p.Occupied || p.Speed != "" {
		t.Errorf("port 2 must be empty: %+v", p)
	}
	if p := a.Ports[2]; !p.Occupied || p.Path != "/dev/sr0" || p.Device != "HL-DT-ST DVDRAM GUD1N" {
		t.Errorf("port 3: %+v", p)
	}
	n := cs[1]
	if n.Type != "NVMe" || len(n.Ports) != 1 || n.Ports[0].Device != "Samsung SSD 980 PRO 1TB" || n.Ports[0].Path != "/dev/nvme0n1" || n.Ports[0].Speed != "16.0 GT/s PCIe x4" {
		t.Errorf("nvme: %+v", n)
	}
	sd := cs[2]
	if sd.Type != "SD/MMC" || sd.Driver != "sdhci-iproc" || sd.Location != "fe340000.mmc" || !sd.Ports[0].Occupied || sd.Ports[0].Device != "SD SC32G" || sd.Ports[0].Path != "/dev/mmcblk0" {
		t.Errorf("sd: %+v", sd)
	}
	if p := cs[3].Ports[0]; !p.Occupied || p.Device != "SDIO device (e.g. Wi-Fi)" {
		t.Errorf("sdio: %+v", p)
	}
	if p := cs[4].Ports[0]; p.Occupied {
		t.Errorf("empty mmc slot: %+v", p)
	}
}

func TestParsePCIIDs(t *testing.T) {
	ids := "# comment\n8086  Intel Corporation\n\ta352  Cannon Lake PCH SATA AHCI Controller\n\t\t1028 0001  subsys\n144d  Samsung Electronics Co Ltd\n\ta80a  NVMe SSD Controller PM9A1/PM9A3/980PRO\nC 01  Mass storage controller\n"
	got := parsePCIIDs(ids, map[string]bool{"8086": true, "8086:a352": true, "144d": true, "144d:a80a": true})
	if got["8086"] != "Intel Corporation" || got["8086:a352"] != "Cannon Lake PCH SATA AHCI Controller" || got["144d:a80a"] != "NVMe SSD Controller PM9A1/PM9A3/980PRO" {
		t.Errorf("parsePCIIDs: %+v", got)
	}
}
