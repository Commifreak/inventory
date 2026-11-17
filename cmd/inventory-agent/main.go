// Command inventory-agent collects inventory data and reports it to an
// Inventory server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/commifreak/inventory/internal/agent"
	"github.com/commifreak/inventory/internal/tag"
)

const usage = `Inventory agent %s

Usage:
  inventory-agent install [--server URL --token TOKEN] [--quiet]
  inventory-agent uninstall [--quiet]
  inventory-agent status
  inventory-agent proxy [URL]               show the proxy used for URL (default: server)
  inventory-agent collect [collector ...]   print collected data as JSON
  inventory-agent run                       run in the foreground
  inventory-agent version

On Windows, double-clicking the installer downloaded from the server installs
the agent. Silent installation: inventory-agent-setup.exe /install /quiet
`

func main() {
	args := normalizeArgs(os.Args[1:])
	if handled, code := agent.PlatformMain(args); handled {
		os.Exit(code)
	}
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, usage, agent.Version)
		os.Exit(2)
	}
	switch args[0] {
	case "version":
		fmt.Println(agent.Version)
	case "selftest":
		// Used by the updater: the binary must start and report its version.
		fmt.Println(agent.Version)
	case "run":
		os.Exit(runForeground())
	case "proxy":
		target := ""
		if len(args) > 1 {
			target = args[1]
		} else if cfg, err := agent.LoadConfig(); err == nil {
			target = cfg.ServerURL
		}
		if target == "" {
			fmt.Fprintln(os.Stderr, "usage: inventory-agent proxy URL")
			os.Exit(2)
		}
		fmt.Println(proxyLine(target))
	case "collect":
		rep := agent.CollectAll(context.Background(), args[1:])
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	case "install":
		fs := flag.NewFlagSet("install", flag.ExitOnError)
		server := fs.String("server", "", "server URL")
		token := fs.String("token", "", "enrollment token")
		quiet := fs.Bool("quiet", false, "no dialogs")
		_ = fs.Parse(args[1:])
		if *server == "" && *token == "" {
			if exe, err := os.Executable(); err == nil {
				if t, err := tag.ReadFile(exe); err == nil {
					*server, *token = t.ServerURL, t.EnrollmentToken
				}
			}
		}
		if err := agent.InstallInteractive(*server, *token, *quiet); err != nil {
			fmt.Fprintln(os.Stderr, "install failed:", err)
			os.Exit(1)
		}
	case "uninstall":
		quiet := len(args) > 1 && args[1] == "--quiet"
		if err := agent.UninstallInteractive(quiet); err != nil {
			fmt.Fprintln(os.Stderr, "uninstall failed:", err)
			os.Exit(1)
		}
	case "status":
		printStatus()
	case "help", "--help", "-h":
		fmt.Printf(usage, agent.Version)
	default:
		fmt.Fprintf(os.Stderr, usage, agent.Version)
		os.Exit(2)
	}
}

// normalizeArgs accepts Windows style switches (/install /quiet).
func normalizeArgs(in []string) []string {
	var out []string
	for _, a := range in {
		switch strings.ToLower(a) {
		case "/install", "-install", "--install":
			a = "install"
		case "/uninstall", "-uninstall", "--uninstall":
			a = "uninstall"
		case "/quiet", "/q", "/s", "/silent", "-q", "--silent":
			a = "--quiet"
		}
		out = append(out, a)
	}
	// "--quiet install" -> "install --quiet"
	if len(out) > 1 && out[0] == "--quiet" {
		out[0], out[1] = out[1], out[0]
	}
	return out
}

func runForeground() int {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := agent.Run(ctx, log)
	switch {
	case errors.Is(err, agent.ErrRestart):
		return 3 // the service manager restarts us with the new binary
	case err != nil:
		log.Error("agent stopped", "err", err)
		return 1
	}
	return 0
}

func logLevel() slog.Level {
	if strings.EqualFold(os.Getenv("INVENTORY_DEBUG"), "1") {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// proxyLine describes the proxy the agent uses for target.
func proxyLine(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "invalid URL: " + target
	}
	p, source, err := agent.ProxyFor(u)
	switch {
	case err != nil:
		return "error: " + err.Error()
	case p == nil:
		return "none (direct connection)"
	}
	return p.Redacted() + " (" + source + ")"
}

func printStatus() {
	fmt.Println("version:   ", agent.Version)
	fmt.Println("installed: ", agent.IsInstalled())
	cfg, err := agent.LoadConfig()
	if err != nil {
		fmt.Println("config:    ", err)
		return
	}
	fmt.Println("server:    ", cfg.ServerURL)
	fmt.Println("proxy:     ", proxyLine(cfg.ServerURL))
	fmt.Println("device id: ", cfg.DeviceID)
	fmt.Println("enrolled:  ", cfg.Credential != "")
	st := agent.LoadState()
	fmt.Println("check-in:  ", st.LastCheckin.Format("2006-01-02 15:04:05"))
	if st.LastError != "" {
		fmt.Println("last error:", st.LastError)
	}
	if st.Revoked {
		fmt.Println("revoked:    yes (the server stopped accepting data from this device)")
	}
	for k, v := range st.LastRun {
		fmt.Printf("  %-10s %s\n", k, v.Format("2006-01-02 15:04:05"))
	}
}
