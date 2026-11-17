package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const unitFile = `[Unit]
Description=Inventory Agent
Documentation=https://github.com/commifreak/inventory
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/lib/inventory-agent/inventory-agent run
Restart=always
RestartSec=10
Nice=10
IOSchedulingClass=idle
ProtectSystem=full
ReadWritePaths=/usr/local/lib/inventory-agent /var/lib/inventory-agent
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

// Install copies the running binary into place, writes the configuration
// and starts the systemd service.
func Install(serverURL, token string) error {
	if os.Geteuid() != 0 {
		return errors.New("installation requires root")
	}
	if !fileExists("/run/systemd/system") {
		return errors.New("systemd is required")
	}
	if err := writeInstallConfig(serverURL, token); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	if err := installBinary(self, BinaryPath()); err != nil {
		return err
	}
	_ = os.Remove(symlinkPath)
	_ = os.Symlink(BinaryPath(), symlinkPath)
	if err := os.WriteFile(unitPath, []byte(unitFile), 0o644); err != nil {
		return err
	}
	ctx := context.Background()
	if _, err := runCmd(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := runCmd(ctx, "systemctl", "enable", serviceName); err != nil {
		return err
	}
	if _, err := runCmd(ctx, "systemctl", "restart", serviceName); err != nil {
		return err
	}
	fmt.Println("inventory: agent installed and started (systemctl status inventory-agent)")
	return nil
}

// writeInstallConfig keeps an existing enrollment for the same server.
func writeInstallConfig(serverURL, token string) error {
	if serverURL == "" || token == "" {
		if c, err := LoadConfig(); err == nil && c.ServerURL != "" {
			return nil // reinstall/update without new parameters
		}
		return errors.New("server URL and enrollment token are required")
	}
	if c, err := LoadConfig(); err == nil && c.ServerURL == serverURL && c.Credential != "" {
		return nil // already enrolled with this server
	}
	if err := os.MkdirAll(DataDir(), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(DataDir(), 0o700)
	_ = os.Remove(statePath())
	return SaveConfig(&Config{ServerURL: strings.TrimRight(serverURL, "/"), EnrollmentToken: token})
}

// installBinary copies src to dst atomically (src may be dst's own file).
func installBinary(src, dst string) error {
	if s, err := filepath.EvalSymlinks(src); err == nil {
		src = s
	}
	if d, err := filepath.EvalSymlinks(dst); err == nil && d == src {
		return nil
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// Uninstall stops and removes the agent including its data.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstalling requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = runCmd(ctx, "systemctl", "disable", "--now", serviceName)
	_ = os.Remove(unitPath)
	_, _ = runCmd(ctx, "systemctl", "daemon-reload")
	_ = os.Remove(symlinkPath)
	_ = os.RemoveAll(installDir)
	_ = os.RemoveAll(DataDir())
	fmt.Println("inventory: agent removed")
	return nil
}

// IsInstalled reports whether the service is set up.
func IsInstalled() bool { return fileExists(unitPath) && fileExists(configPath()) }
