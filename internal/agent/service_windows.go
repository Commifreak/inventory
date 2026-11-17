package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/commifreak/inventory/internal/tag"
)

// PlatformMain handles the Windows service entry point and the double-click
// installer experience.
func PlatformMain(args []string) (bool, int) {
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		return true, runService()
	}
	if len(args) > 0 {
		return false, 0
	}
	// Started without arguments, typically by double-click.
	exe, _ := os.Executable()
	t, err := tag.ReadFile(exe)
	if err != nil {
		if IsInstalled() {
			cfg, _ := LoadConfig()
			server := ""
			if cfg != nil {
				server = cfg.ServerURL
			}
			messageBox(productName, fmt.Sprintf("%s %s is installed and reports to\n%s", productName, Version, server), mbIconInfo)
			return true, 0
		}
		messageBox(productName, "This file contains no server configuration.\n\nPlease download the installer from your Inventory server (Settings → Install agents).", mbIconWarning)
		return true, 1
	}
	if !isElevated() {
		if err := relaunchElevated("install"); err != nil {
			if !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "1223") {
				messageBox(productName, "Installation failed: "+err.Error(), mbIconError)
			}
			return true, 1
		}
		return true, 0
	}
	if err := InstallInteractive(t.ServerURL, t.EnrollmentToken, false); err != nil {
		return true, 1
	}
	return true, 0
}

// InstallInteractive installs the agent and reports the result in a dialog
// unless quiet is set.
func InstallInteractive(server, token string, quiet bool) error {
	if !isElevated() {
		if quiet {
			return errors.New("administrator rights required")
		}
		args := "install"
		if server != "" {
			args += fmt.Sprintf(` --server "%s" --token "%s"`, server, token)
		}
		return relaunchElevated(args)
	}
	err := Install(server, token)
	if !quiet {
		if err != nil {
			messageBox(productName, "Installation failed:\n\n"+err.Error(), mbIconError)
		} else {
			cfg, _ := LoadConfig()
			srv := server
			if cfg != nil {
				srv = cfg.ServerURL
			}
			messageBox(productName, fmt.Sprintf("%s %s was installed.\n\nThis computer now reports to\n%s", productName, Version, srv), mbIconInfo)
		}
	}
	return err
}

// UninstallInteractive removes the agent after confirmation.
func UninstallInteractive(quiet bool) error {
	if !isElevated() {
		if quiet {
			return errors.New("administrator rights required")
		}
		return relaunchElevated("uninstall")
	}
	if !quiet && messageBox(productName, "Remove the Inventory Agent from this computer?", mbOKCancel|mbIconWarning) != idOK {
		return nil
	}
	err := Uninstall()
	if !quiet {
		if err != nil {
			messageBox(productName, "Uninstall failed:\n\n"+err.Error(), mbIconError)
		} else {
			messageBox(productName, "The Inventory Agent was removed.", mbIconInfo)
		}
	}
	return err
}

// ---------------------------------------------------------------------------
// service
// ---------------------------------------------------------------------------

type agentService struct{ log *slog.Logger }

func runService() int {
	lw := newRotatingLog(filepath.Join(DataDir(), "agent.log"), 5<<20)
	log := slog.New(slog.NewTextHandler(lw, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := svc.Run(serviceName, &agentService{log: log}); err != nil {
		log.Error("service failed", "err", err)
		return 1
	}
	return 0
}

func (s *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s.log) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if errors.Is(err, ErrRestart) {
				// Exit with an error code: the service recovery actions restart
				// the service, which then runs the new binary.
				s.log.Info("restarting service")
				return false, 1
			}
			if err != nil {
				s.log.Error("agent stopped", "err", err)
				return false, 2
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// rotatingLog is a minimal size based log rotation.
type rotatingLog struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func newRotatingLog(path string, max int64) io.Writer {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	return &rotatingLog{path: path, max: max}
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return len(p), nil
		}
		st, _ := f.Stat()
		l.f, l.size = f, st.Size()
	}
	if l.size+int64(len(p)) > l.max {
		l.f.Close()
		_ = os.Rename(l.path, l.path+".1")
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			l.f = nil
			return len(p), nil
		}
		l.f, l.size = f, 0
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}
