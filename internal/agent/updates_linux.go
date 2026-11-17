package agent

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// collectUpdatesLinux reports pending package updates. It only reads the
// package manager caches and never refreshes them (no changes to the system).
func collectUpdatesLinux(ctx context.Context, _ *State) (any, []string, error) {
	switch {
	case hasCmd("apt-get") && hasCmd("dpkg-query"):
		return aptUpdates(ctx)
	case hasCmd("dnf") || hasCmd("dnf5"):
		return dnfUpdates(ctx)
	case hasCmd("zypper"):
		return zypperUpdates(ctx)
	case hasCmd("pacman"):
		return pacmanUpdates(ctx)
	}
	return nil, nil, fmt.Errorf("no supported package manager found (apt, dnf, zypper, pacman)")
}

func modTime(paths ...string) time.Time {
	var t time.Time
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.ModTime().After(t) {
			t = st.ModTime()
		}
	}
	return t
}

func systemdEnabled(ctx context.Context, units ...string) (bool, string) {
	for _, u := range units {
		if out, err := runCmd(ctx, "systemctl", "is-enabled", u); err == nil && strings.TrimSpace(out) == "enabled" {
			return true, u + " enabled"
		}
	}
	return false, ""
}

// ---------------------------------------------------------------------------
// apt
// ---------------------------------------------------------------------------

var aptUpgradableRe = regexp.MustCompile(`^(\S+)/(\S+)\s+(\S+)\s+(\S+)(?:\s+\[upgradable from: ([^\]]+)\])?`)

func aptUpdates(ctx context.Context) (any, []string, error) {
	var warns []string
	u := protocol.UpdatesData{Manager: "apt"}
	out, err := runCmd(ctx, "apt", "list", "--upgradable")
	if err != nil {
		return nil, nil, err
	}
	for _, l := range strings.Split(out, "\n") {
		m := aptUpgradableRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		sec := strings.Contains(m[2], "-security") || strings.Contains(m[2], "/updates")
		u.Pending = append(u.Pending, protocol.PendingUpdate{Title: m[1], Version: m[5] + " → " + m[3], Category: m[2], Security: sec})
		if sec {
			u.SecurityCount++
		}
	}
	u.PendingCount = len(u.Pending)
	u.LastSearch = modTime("/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists", "/var/cache/apt/pkgcache.bin")
	u.LastInstall = lastDpkgInstall()
	if fileExists("/var/run/reboot-required") {
		u.RebootRequired = true
		if pk := readTrim("/var/run/reboot-required.pkgs"); pk != "" {
			u.RebootReasons = uniqueStrings(strings.Fields(pk))
		}
	}
	// unattended-upgrades
	auto := false
	if _, err := runCmd(ctx, "dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"); err == nil {
		files, _ := filepath.Glob("/etc/apt/apt.conf.d/*")
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if regexp.MustCompile(`(?m)^\s*APT::Periodic::Unattended-Upgrade\s+"(1|always)"`).Match(b) {
				auto = true
			}
		}
		if auto {
			u.AutoUpdatesInfo = "unattended-upgrades"
		} else {
			u.AutoUpdatesInfo = "unattended-upgrades installed but disabled"
		}
	} else {
		u.AutoUpdatesInfo = "unattended-upgrades not installed"
	}
	u.AutoUpdates = boolPtr(auto)
	u.History = aptHistory()
	if fileExists("/var/log/unattended-upgrades/unattended-upgrades.log") {
		u.History = append(u.History, unattendedErrors()...)
	}
	return u, warns, nil
}

func lastDpkgInstall() time.Time {
	f, err := os.Open("/var/log/dpkg.log")
	if err != nil {
		return time.Time{}
	}
	defer f.Close()
	var last time.Time
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if strings.Contains(l, " status installed ") && len(l) > 19 {
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", l[:19], time.Local); err == nil {
				last = t
			}
		}
	}
	return last
}

// aptHistory parses /var/log/apt/history.log into history entries.
func aptHistory() []protocol.UpdateHistoryEntry {
	b, err := os.ReadFile("/var/log/apt/history.log")
	if err != nil {
		return nil
	}
	var out []protocol.UpdateHistoryEntry
	for _, block := range strings.Split(string(b), "\n\n") {
		fields := map[string]string{}
		for _, l := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(l, ": ")
			if ok {
				fields[k] = v
			}
		}
		start := fields["Start-Date"]
		if start == "" {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02  15:04:05", start, time.Local)
		if err != nil {
			continue
		}
		var parts []string
		for _, op := range []string{"Install", "Upgrade", "Remove", "Purge"} {
			if v := fields[op]; v != "" {
				n := strings.Count(v, "), ") + 1
				parts = append(parts, fmt.Sprintf("%s %d", strings.ToLower(op), n))
			}
		}
		if len(parts) == 0 {
			continue
		}
		e := protocol.UpdateHistoryEntry{Title: "apt: " + strings.Join(parts, ", "), Date: t, Result: "Succeeded", Message: truncateStr(fields["Commandline"], 200)}
		if er := fields["Error"]; er != "" {
			e.Result, e.Message = "Failed", truncateStr(er, 300)
		}
		out = append(out, e)
	}
	if len(out) > 30 {
		out = out[len(out)-30:]
	}
	// newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func unattendedErrors() []protocol.UpdateHistoryEntry {
	f, err := os.Open("/var/log/unattended-upgrades/unattended-upgrades.log")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []protocol.UpdateHistoryEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if !strings.Contains(l, " ERROR ") || len(l) < 19 {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", l[:19], time.Local)
		if err != nil {
			continue
		}
		msg := strings.TrimSpace(l[strings.Index(l, " ERROR ")+7:])
		out = append(out, protocol.UpdateHistoryEntry{Title: "unattended-upgrades", Date: t, Result: "Failed", Message: truncateStr(msg, 300)})
	}
	if len(out) > 10 {
		out = out[len(out)-10:]
	}
	return out
}

// ---------------------------------------------------------------------------
// dnf
// ---------------------------------------------------------------------------

func dnfUpdates(ctx context.Context) (any, []string, error) {
	var warns []string
	dnf := "dnf"
	if !hasCmd(dnf) {
		dnf = "dnf5"
	}
	u := protocol.UpdatesData{Manager: dnf}
	out, err := runCmd(ctx, dnf, "-q", "--cacheonly", "check-update")
	code := exitCode(err)
	if err != nil && code != 100 {
		// Cache missing: allow a metadata refresh (read-only for the system).
		out, err = runCmd(ctx, dnf, "-q", "check-update")
		code = exitCode(err)
		if err != nil && code != 100 {
			u.SearchError = err.Error()
		}
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && strings.Contains(f[0], ".") && !strings.HasPrefix(l, " ") {
			if strings.HasPrefix(f[0], "Obsoleting") {
				break
			}
			u.Pending = append(u.Pending, protocol.PendingUpdate{Title: f[0], Version: f[1], Category: f[2]})
		}
	}
	u.PendingCount = len(u.Pending)
	if sec, err := runCmd(ctx, dnf, "-q", "--cacheonly", "updateinfo", "list", "--security", "--updates"); err == nil {
		secPkgs := map[string]bool{}
		for _, l := range strings.Split(sec, "\n") {
			f := strings.Fields(l)
			if len(f) >= 3 {
				secPkgs[f[len(f)-1]] = true
			}
		}
		u.SecurityCount = len(secPkgs)
		for i := range u.Pending {
			name := strings.SplitN(u.Pending[i].Title, ".", 2)[0]
			for p := range secPkgs {
				if strings.HasPrefix(p, name+"-") {
					u.Pending[i].Security = true
				}
			}
		}
	}
	u.LastSearch = modTime("/var/cache/dnf", "/var/cache/libdnf5")
	if out, err := runCmd(ctx, "rpm", "-qa", "--qf", "%{INSTALLTIME}\n"); err == nil {
		var max int64
		for _, l := range strings.Fields(out) {
			var n int64
			fmt.Sscan(l, &n)
			if n > max {
				max = n
			}
		}
		if max > 0 {
			u.LastInstall = time.Unix(max, 0)
		}
	}
	// needs-restarting -r: exit 1 = reboot required
	var nrErr error
	if hasCmd("needs-restarting") {
		_, nrErr = runCmd(ctx, "needs-restarting", "-r")
	} else {
		_, nrErr = runCmd(ctx, dnf, "needs-restarting", "-r")
	}
	if exitCode(nrErr) == 1 {
		u.RebootRequired = true
	}
	auto, info := systemdEnabled(ctx, "dnf-automatic-install.timer", "dnf-automatic.timer", "dnf5-automatic.timer")
	u.AutoUpdates, u.AutoUpdatesInfo = boolPtr(auto), info
	return u, warns, nil
}

// ---------------------------------------------------------------------------
// zypper
// ---------------------------------------------------------------------------

func zypperUpdates(ctx context.Context) (any, []string, error) {
	u := protocol.UpdatesData{Manager: "zypper"}
	out, err := runCmd(ctx, "zypper", "--non-interactive", "--no-refresh", "--xmlout", "list-updates")
	if err != nil {
		return nil, nil, err
	}
	var r struct {
		Updates []struct {
			Name    string `xml:"name,attr"`
			Edition string `xml:"edition,attr"`
			Kind    string `xml:"kind,attr"`
			Repo    struct {
				Alias string `xml:"alias,attr"`
			} `xml:"source"`
		} `xml:"update-status>update-list>update"`
	}
	_ = xml.Unmarshal([]byte(out), &r)
	for _, up := range r.Updates {
		u.Pending = append(u.Pending, protocol.PendingUpdate{Title: up.Name, Version: up.Edition, Category: up.Repo.Alias})
	}
	u.PendingCount = len(u.Pending)
	if sec, err := runCmd(ctx, "zypper", "--non-interactive", "--no-refresh", "--xmlout", "list-patches", "--category", "security"); err == nil {
		u.SecurityCount = strings.Count(sec, "<update ")
	}
	_, nr := runCmd(ctx, "zypper", "needs-rebooting")
	u.RebootRequired = exitCode(nr) == 102 || fileExists("/run/reboot-needed")
	u.LastSearch = modTime("/var/cache/zypp/raw")
	return u, nil, nil
}

// ---------------------------------------------------------------------------
// pacman
// ---------------------------------------------------------------------------

func pacmanUpdates(ctx context.Context) (any, []string, error) {
	u := protocol.UpdatesData{Manager: "pacman"}
	out, err := runCmd(ctx, "pacman", "-Qu")
	if err != nil && exitCode(err) != 1 { // exit 1 = nothing to update
		return nil, nil, err
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 4 {
			u.Pending = append(u.Pending, protocol.PendingUpdate{Title: f[0], Version: f[1] + " → " + f[3]})
		}
	}
	u.PendingCount = len(u.Pending)
	u.LastSearch = modTime("/var/lib/pacman/sync")
	// Kernel updated but not running: modules of the running kernel are gone.
	if rel := readTrim("/proc/sys/kernel/osrelease"); rel != "" && !fileExists("/usr/lib/modules/"+rel) {
		u.RebootRequired = true
		u.RebootReasons = []string{"kernel"}
	}
	if b, err := os.ReadFile("/var/log/pacman.log"); err == nil {
		re := regexp.MustCompile(`(?m)^\[([0-9T:+\-]+)\] \[ALPM\] (upgraded|installed) `)
		if m := re.FindAllStringSubmatch(string(b), -1); len(m) > 0 {
			if t, err := time.Parse("2006-01-02T15:04:05-0700", m[len(m)-1][1]); err == nil {
				u.LastInstall = t
			}
		}
	}
	return u, nil, nil
}
