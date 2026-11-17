package agent

// Installation paths on macOS.
const (
	installDir  = "/Library/Application Support/Inventory Agent"
	dataDir     = "/Library/Application Support/Inventory Agent/data"
	binaryName  = "inventory-agent"
	symlinkPath = "/usr/local/bin/inventory-agent"
	plistPath   = "/Library/LaunchDaemons/io.github.commifreak.inventory-agent.plist"
	serviceName = "io.github.commifreak.inventory-agent"
)

// DataDir holds config and state.
func DataDir() string { return dataDir }

// BinaryPath is the installed agent binary.
func BinaryPath() string { return installDir + "/" + binaryName }
