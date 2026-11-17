package agent

// pciVendorFallback names common storage vendors when pci.ids is missing.
var pciVendorFallback = map[string]string{
	"8086": "Intel", "1022": "AMD", "144d": "Samsung", "1b4b": "Marvell", "1000": "Broadcom / LSI", "9005": "Microchip / Adaptec",
	"1b21": "ASMedia", "197b": "JMicron", "15b7": "Western Digital / SanDisk", "1c5c": "SK hynix", "1987": "Phison", "126f": "Silicon Motion",
	"1e0f": "KIOXIA", "1344": "Micron", "c0a9": "Micron / Crucial", "1179": "Toshiba", "2646": "Kingston", "1cc1": "ADATA", "1e4b": "MAXIO",
	"1bb1": "Seagate", "1af4": "Red Hat (virtio)", "10de": "NVIDIA", "1d79": "Transcend", "1dbe": "INNOGRIT", "1ed0": "Biwin",
}
