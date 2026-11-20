package agent

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/commifreak/inventory/internal/protocol"
)

// linuxStorageControllers lists PCI mass storage controllers and SD/MMC hosts
// from sysfs (sys is "/sys", relocatable for tests). SATA/IDE ports come from
// libata (ataN with link speed, empty ports included), NVMe controllers have
// exactly one device, other controllers (SAS/RAID/virtio) list the attached
// block devices only.
func linuxStorageControllers(sys string) []protocol.StorageController {
	var out []protocol.StorageController
	devs, _ := filepath.Glob(filepath.Join(sys, "bus/pci/devices/*"))
	type pciDev struct {
		path, vendor, device string
		class                uint64
	}
	var found []pciDev
	wanted := map[string]bool{}
	for _, d := range devs {
		class, err := strconv.ParseUint(strings.TrimPrefix(readTrim(filepath.Join(d, "class")), "0x"), 16, 32)
		if err != nil || class>>16 != 0x01 {
			continue
		}
		v := strings.TrimPrefix(readTrim(filepath.Join(d, "vendor")), "0x")
		dev := strings.TrimPrefix(readTrim(filepath.Join(d, "device")), "0x")
		found = append(found, pciDev{d, v, dev, class})
		wanted[v] = true
		wanted[v+":"+dev] = true
	}
	names := pciIDNames(wanted)
	for _, p := range found {
		sub, progIf := (p.class>>8)&0xff, p.class&0xff
		c := protocol.StorageController{Type: pciStorageType(sub, progIf), Location: filepath.Base(p.path)}
		if drv, err := os.Readlink(filepath.Join(p.path, "driver")); err == nil {
			c.Driver = filepath.Base(drv)
		}
		c.Vendor = names[p.vendor]
		if c.Vendor == "" {
			c.Vendor = pciVendorFallback[p.vendor]
		}
		c.Name = names[p.vendor+":"+p.device]
		if c.Name == "" {
			c.Name = strings.TrimSpace(c.Vendor+" "+c.Type+" controller") + " [" + p.vendor + ":" + p.device + "]"
		}
		switch {
		case hasGlob(filepath.Join(p.path, "ata[0-9]*")):
			c.Ports, c.PortsComplete = ataPorts(sys, p.path), true
		case hasGlob(filepath.Join(p.path, "nvme/nvme[0-9]*")):
			c.Ports, c.PortsComplete = nvmePorts(p.path), true
		default:
			c.Ports = blockPorts(sys, p.path)
		}
		out = append(out, c)
	}
	out = append(out, mmcHosts(sys)...)
	return out
}

func hasGlob(pattern string) bool {
	m, _ := filepath.Glob(pattern)
	return len(m) > 0
}

func pciStorageType(sub, progIf uint64) string {
	switch sub {
	case 0x00:
		return "SCSI"
	case 0x01:
		return "IDE"
	case 0x04:
		return "RAID"
	case 0x05:
		return "ATA"
	case 0x06:
		if progIf == 0x01 {
			return "SATA (AHCI)"
		}
		return "SATA"
	case 0x07:
		return "SAS"
	case 0x08:
		if progIf == 0x02 {
			return "NVMe"
		}
		return "NVM"
	}
	return "storage"
}

// ataPorts lists the libata ports of a controller (ataN directories).
func ataPorts(sys, dev string) []protocol.StoragePort {
	dirs, _ := filepath.Glob(filepath.Join(dev, "ata[0-9]*"))
	num := func(p string) int { n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(p), "ata")); return n }
	sort.Slice(dirs, func(i, j int) bool { return num(dirs[i]) < num(dirs[j]) })
	var out []protocol.StoragePort
	for i, ata := range dirs {
		n := strings.TrimPrefix(filepath.Base(ata), "ata")
		link := filepath.Join(ata, "link"+n)
		port := protocol.StoragePort{Port: strconv.Itoa(i + 1)}
		spd := readTrim(filepath.Join(link, "ata_link", "link"+n, "sata_spd"))
		if spd != "" && spd != "<unknown>" {
			port.Occupied, port.Speed = true, spd
		}
		// libata creates devN.M for every port; its class says whether a
		// device is attached ("none" for empty ports).
		classes, _ := filepath.Glob(filepath.Join(link, "dev"+n+".*", "ata_device", "dev"+n+".*", "class"))
		for _, c := range classes {
			if v := readTrim(c); v != "" && v != "none" {
				port.Occupied = true
			}
		}
		if blocks, _ := filepath.Glob(filepath.Join(ata, "host*/target*/*/block/*")); len(blocks) > 0 {
			name := filepath.Base(blocks[0])
			port.Occupied, port.Path = true, "/dev/"+name
			port.Device = blockModel(sys, name)
		}
		out = append(out, port)
	}
	return out
}

func nvmePorts(dev string) []protocol.StoragePort {
	ctrls, _ := filepath.Glob(filepath.Join(dev, "nvme/nvme[0-9]*"))
	var out []protocol.StoragePort
	for _, c := range ctrls {
		port := protocol.StoragePort{Port: strconv.Itoa(len(out) + 1), Occupied: true, Device: readTrim(filepath.Join(c, "model"))}
		if ns, _ := filepath.Glob(filepath.Join(c, filepath.Base(c)+"n[0-9]*")); len(ns) > 0 {
			port.Path = "/dev/" + filepath.Base(ns[0])
		} else if ns, _ := filepath.Glob(filepath.Join(c, "nvme[0-9]*n[0-9]*")); len(ns) > 0 {
			port.Path = "/dev/" + filepath.Base(ns[0])
		}
		if speed := readTrim(filepath.Join(dev, "current_link_speed")); speed != "" && !strings.HasPrefix(speed, "Unknown") {
			port.Speed = speed
			if w := readTrim(filepath.Join(dev, "current_link_width")); w != "" {
				port.Speed += " x" + w
			}
		}
		out = append(out, port)
	}
	return out
}

// blockPorts lists the block devices below a controller (only occupied ports
// are known for SAS/RAID/virtio controllers).
func blockPorts(sys, dev string) []protocol.StoragePort {
	var blocks []string
	for _, pat := range []string{"host*/target*/*/block/*", "*/host*/target*/*/block/*", "*/host*/port*/end_device*/target*/*/block/*", "virtio*/block/*"} {
		m, _ := filepath.Glob(filepath.Join(dev, pat))
		blocks = append(blocks, m...)
	}
	sort.Strings(blocks)
	var out []protocol.StoragePort
	seen := map[string]bool{}
	for _, b := range blocks {
		name := filepath.Base(b)
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, protocol.StoragePort{Port: strconv.Itoa(len(out) + 1), Occupied: true, Path: "/dev/" + name, Device: blockModel(sys, name)})
	}
	return out
}

func blockModel(sys, name string) string {
	dev := filepath.Join(sys, "block", name, "device")
	vendor := readTrim(filepath.Join(dev, "vendor"))
	if strings.HasPrefix(vendor, "0x") { // virtio: PCI vendor ID, not a name
		vendor = ""
	}
	model := strings.TrimSpace(vendor + " " + readTrim(filepath.Join(dev, "model")))
	if model == "" {
		model = readTrim(filepath.Join(dev, "name"))
	}
	if strings.HasPrefix(model, "ATA ") {
		model = strings.TrimPrefix(model, "ATA ")
	}
	return model
}

// mmcHosts lists SD/MMC host controllers (SD card slots, eMMC, SDIO).
func mmcHosts(sys string) []protocol.StorageController {
	hosts, _ := filepath.Glob(filepath.Join(sys, "class/mmc_host/mmc[0-9]*"))
	sort.Strings(hosts)
	var out []protocol.StorageController
	for _, h := range hosts {
		name := filepath.Base(h)
		c := protocol.StorageController{Name: "SD/MMC host " + name, Type: "SD/MMC", PortsComplete: true}
		if drv, err := os.Readlink(filepath.Join(h, "device", "driver")); err == nil {
			c.Driver = filepath.Base(drv)
		}
		if real, err := filepath.EvalSymlinks(filepath.Join(h, "device")); err == nil {
			c.Location = filepath.Base(real)
		}
		port := protocol.StoragePort{Port: "1"}
		if cards, _ := filepath.Glob(filepath.Join(h, name+":*")); len(cards) > 0 {
			card := cards[0]
			port.Occupied = true
			typ := readTrim(filepath.Join(card, "type")) // SD, MMC, SDIO
			port.Device = strings.TrimSpace(readTrim(filepath.Join(card, "name")))
			switch {
			case port.Device == "" && typ == "SDIO":
				port.Device = "SDIO device (e.g. Wi-Fi)"
			case typ != "":
				port.Device = strings.TrimSpace(typ + " " + port.Device)
			}
			if blocks, _ := filepath.Glob(filepath.Join(card, "block/*")); len(blocks) > 0 {
				port.Path = "/dev/" + filepath.Base(blocks[0])
			}
		}
		c.Ports = []protocol.StoragePort{port}
		out = append(out, c)
	}
	return out
}

var pciIDsFiles = []string{"/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids", "/usr/share/pci.ids"}

// pciIDNames looks up vendor ("8086") and device ("8086:a352") names in the
// system's pci.ids, if installed.
func pciIDNames(wanted map[string]bool) map[string]string {
	out := map[string]string{}
	for _, f := range pciIDsFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		return parsePCIIDs(string(b), wanted)
	}
	return out
}

func parsePCIIDs(content string, wanted map[string]bool) map[string]string {
	out := map[string]string{}
	vendor := ""
	for _, line := range strings.Split(content, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "C ") { // class section at the end
			break
		}
		if line[0] != '\t' {
			id, name, ok := strings.Cut(line, "  ")
			if !ok {
				continue
			}
			vendor = strings.ToLower(id)
			if wanted[vendor] {
				out[vendor] = strings.TrimSpace(name)
			}
			continue
		}
		if strings.HasPrefix(line, "\t\t") || !wanted[vendor] {
			continue
		}
		id, name, ok := strings.Cut(strings.TrimPrefix(line, "\t"), "  ")
		if ok && wanted[vendor+":"+strings.ToLower(id)] {
			out[vendor+":"+strings.ToLower(id)] = strings.TrimSpace(name)
		}
	}
	return out
}
