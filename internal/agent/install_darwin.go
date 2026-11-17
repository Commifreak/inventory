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

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.github.commifreak.inventory-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Library/Application Support/Inventory Agent/inventory-agent</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>/Library/Application Support/Inventory Agent/data/agent.log</string>
</dict>
</plist>
`

// Install copies the binary, writes the configuration and loads the launchd daemon.
func Install(serverURL, token string) error {
	if os.Geteuid() != 0 {
		return errors.New("installation requires root")
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
	_ = os.MkdirAll(filepath.Dir(symlinkPath), 0o755)
	_ = os.Remove(symlinkPath)
	_ = os.Symlink(BinaryPath(), symlinkPath)
	ctx := context.Background()
	_, _ = runCmd(ctx, "launchctl", "bootout", "system/"+serviceName)
	if err := os.WriteFile(plistPath, []byte(launchdPlist), 0o644); err != nil {
		return err
	}
	if _, err := runCmd(ctx, "launchctl", "bootstrap", "system", plistPath); err != nil {
		return err
	}
	fmt.Println("inventory: agent installed and started")
	return nil
}

func writeInstallConfig(serverURL, token string) error {
	if serverURL == "" || token == "" {
		if c, err := LoadConfig(); err == nil && c.ServerURL != "" {
			return nil
		}
		return errors.New("server URL and enrollment token are required")
	}
	if c, err := LoadConfig(); err == nil && c.ServerURL == serverURL && c.Credential != "" {
		return nil
	}
	if err := os.MkdirAll(DataDir(), 0o700); err != nil {
		return err
	}
	_ = os.Remove(statePath())
	return SaveConfig(&Config{ServerURL: strings.TrimRight(serverURL, "/"), EnrollmentToken: token})
}

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

// Uninstall removes the daemon, binary and data.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("uninstalling requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = runCmd(ctx, "launchctl", "bootout", "system/"+serviceName)
	_ = os.Remove(plistPath)
	_ = os.Remove(symlinkPath)
	_ = os.RemoveAll(installDir)
	fmt.Println("inventory: agent removed")
	return nil
}

// IsInstalled reports whether the daemon is set up.
func IsInstalled() bool { return fileExists(plistPath) && fileExists(configPath()) }
