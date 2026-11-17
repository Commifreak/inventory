package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/commifreak/inventory/internal/tag"
)

// Install copies the agent to Program Files, writes the configuration,
// registers the service (with restart-on-failure recovery actions) and the
// "Apps & features" entry, and starts the service.
func Install(serverURL, token string) error {
	if !isElevated() {
		return errors.New("administrator rights required")
	}
	if err := os.MkdirAll(DataDir(), 0o700); err != nil {
		return err
	}
	if err := restrictDir(DataDir()); err != nil {
		return fmt.Errorf("securing %s: %w", DataDir(), err)
	}
	if err := writeInstallConfig(serverURL, token); err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()

	// Stop a running instance before replacing the binary.
	if s, err := m.OpenService(serviceName); err == nil {
		stopService(s)
		s.Close()
	}
	if err := copySelf(); err != nil {
		return err
	}

	exe := BinaryPath()
	s, err := m.OpenService(serviceName)
	if err != nil {
		s, err = m.CreateService(serviceName, exe, mgr.Config{
			DisplayName:      serviceDisplay,
			Description:      "Collects hardware, disk health, update and software inventory for the Inventory server.",
			StartType:        mgr.StartAutomatic,
			DelayedAutoStart: true,
			ServiceStartName: "LocalSystem",
		})
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
	} else {
		cfg, err := s.Config()
		if err == nil {
			cfg.BinaryPathName = `"` + exe + `"`
			cfg.StartType = mgr.StartAutomatic
			cfg.DelayedAutoStart = true
			_ = s.UpdateConfig(cfg)
		}
	}
	defer s.Close()
	// Restart on failure; the agent exits with an error after self-updates.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, uint32((24 * time.Hour).Seconds()))
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)

	if err := writeUninstallEntry(exe); err != nil {
		return fmt.Errorf("registering uninstall entry: %w", err)
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

func writeInstallConfig(serverURL, token string) error {
	if serverURL == "" || token == "" {
		if c, err := LoadConfig(); err == nil && c.ServerURL != "" {
			return nil
		}
		return errors.New("no server configuration - use the installer downloaded from your Inventory server")
	}
	if c, err := LoadConfig(); err == nil && c.ServerURL == strings.TrimRight(serverURL, "/") && c.Credential != "" {
		return nil // already enrolled with this server (reinstall)
	}
	_ = os.Remove(statePath())
	return SaveConfig(&Config{ServerURL: strings.TrimRight(serverURL, "/"), EnrollmentToken: token})
}

// copySelf installs the running executable (without install tag) to Program Files.
func copySelf() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	dst := BinaryPath()
	if strings.EqualFold(filepath.Clean(self), filepath.Clean(dst)) {
		return nil
	}
	b, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	b = tag.Strip(b)
	if err := os.MkdirAll(installDir(), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	// The old binary may still be locked for a moment after stopping the service.
	if _, err := os.Stat(dst); err == nil {
		_ = os.Remove(dst + ".old")
		if err := os.Rename(dst, dst+".old"); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("replace %s: %w", dst, err)
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	_ = os.Remove(dst + ".old")
	return nil
}

func stopService(s *mgr.Service) {
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return
	}
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
	}
}

func writeUninstallEntry(exe string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	size := uint32(0)
	if st, err := os.Stat(exe); err == nil {
		size = uint32(st.Size() / 1024)
	}
	for name, val := range map[string]string{
		"DisplayName":          productName,
		"DisplayVersion":       Version,
		"Publisher":            "Inventory",
		"DisplayIcon":          exe,
		"InstallLocation":      installDir(),
		"UninstallString":      `"` + exe + `" uninstall`,
		"QuietUninstallString": `"` + exe + `" uninstall --quiet`,
		"URLInfoAbout":         "https://github.com/commifreak/inventory",
	} {
		if err := k.SetStringValue(name, val); err != nil {
			return err
		}
	}
	_ = k.SetDWordValue("NoModify", 1)
	_ = k.SetDWordValue("NoRepair", 1)
	_ = k.SetDWordValue("EstimatedSize", size)
	return nil
}

// updateUninstallVersion keeps the "Apps & features" version current after self-updates.
func updateUninstallVersion() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetStringValue("DisplayVersion", Version)
}

// Uninstall removes service, files, data and the uninstall entry.
func Uninstall() error {
	if !isElevated() {
		return errors.New("administrator rights required")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	if s, err := m.OpenService(serviceName); err == nil {
		stopService(s)
		_ = s.Delete()
		s.Close()
	}
	m.Disconnect()
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey)
	_ = os.RemoveAll(DataDir())
	// The running executable cannot delete itself: remove the folder shortly after we exit.
	self, _ := os.Executable()
	if strings.HasPrefix(strings.ToLower(self), strings.ToLower(installDir())) {
		cmd := exec.Command("cmd.exe", "/c", fmt.Sprintf(`ping 127.0.0.1 -n 4 >nul & rmdir /s /q "%s"`, installDir()))
		hideWindow(cmd)
		_ = cmd.Start()
	} else {
		_ = os.RemoveAll(installDir())
	}
	return nil
}

// IsInstalled reports whether the service exists.
func IsInstalled() bool {
	m, err := mgr.Connect()
	if err != nil {
		return fileExists(BinaryPath())
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}
