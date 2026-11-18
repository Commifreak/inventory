package agent

import "os"

// Installation paths on Linux.
const (
	installDir  = "/usr/local/lib/inventory-agent"
	dataDir     = "/var/lib/inventory-agent"
	binaryName  = "inventory-agent"
	symlinkPath = "/usr/local/bin/inventory-agent"
	unitPath    = "/etc/systemd/system/inventory-agent.service"
	serviceName = "inventory-agent"
)

// testRoot relocates all paths (tests and development only).
var testRoot = os.Getenv("INVENTORY_AGENT_ROOT")

// DataDir holds config and state.
func DataDir() string {
	if addonMode {
		return addonDataDir
	}
	if testRoot != "" {
		return testRoot + "/data"
	}
	return dataDir
}

// BinaryPath is the installed agent binary.
func BinaryPath() string {
	if testRoot != "" {
		return testRoot + "/bin/" + binaryName
	}
	return installDir + "/" + binaryName
}
