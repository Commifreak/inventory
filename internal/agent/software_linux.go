package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// ---------------------------------------------------------------------------
// software
// ---------------------------------------------------------------------------

func collectSoftwareLinux(ctx context.Context, _ *State) (any, []string, error) {
	var items []protocol.SoftwareItem
	var warns []string
	found := false
	switch {
	case hasCmd("dpkg-query"):
		found = true
		out, err := runCmd(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${Maintainer}\n")
		if err != nil {
			return nil, nil, err
		}
		for _, l := range strings.Split(out, "\n") {
			f := strings.Split(l, "\t")
			if len(f) < 5 || !strings.HasPrefix(f[3], "ii") {
				continue
			}
			items = append(items, protocol.SoftwareItem{Name: f[0], Version: f[1], Arch: f[2], Publisher: f[4], Source: "dpkg", Scope: "machine"})
		}
	case hasCmd("rpm"):
		found = true
		out, err := runCmd(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME}\n")
		if err != nil {
			return nil, nil, err
		}
		for _, l := range strings.Split(out, "\n") {
			f := strings.Split(l, "\t")
			if len(f) < 5 || f[0] == "gpg-pubkey" {
				continue
			}
			it := protocol.SoftwareItem{Name: f[0], Version: f[1], Arch: f[2], Publisher: strings.TrimPrefix(f[3], "(none)"), Source: "rpm", Scope: "machine"}
			if n, err := strconv.ParseInt(f[4], 10, 64); err == nil {
				it.InstallDate = time.Unix(n, 0).Format("2006-01-02")
			}
			items = append(items, it)
		}
	case hasCmd("pacman"):
		found = true
		out, err := runCmd(ctx, "pacman", "-Q")
		if err != nil {
			return nil, nil, err
		}
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) == 2 {
				items = append(items, protocol.SoftwareItem{Name: f[0], Version: f[1], Source: "pacman", Scope: "machine"})
			}
		}
	}
	if hasCmd("snap") {
		found = true
		if out, err := runCmd(ctx, "snap", "list", "--color=never", "--unicode=never"); err == nil {
			for i, l := range strings.Split(out, "\n") {
				f := strings.Fields(l)
				if i == 0 || len(f) < 5 {
					continue
				}
				items = append(items, protocol.SoftwareItem{Name: f[0], Version: f[1], Publisher: strings.TrimSuffix(f[4], "*"), Source: "snap", Scope: "machine"})
			}
		} else {
			warns = append(warns, "snap: "+err.Error())
		}
	}
	if hasCmd("flatpak") {
		found = true
		if out, err := runCmd(ctx, "flatpak", "list", "--app", "--columns=application,version,origin,installation"); err == nil {
			for _, l := range strings.Split(out, "\n") {
				f := strings.Split(l, "\t")
				if len(f) < 4 || f[0] == "" {
					continue
				}
				scope := "machine"
				if f[3] == "user" {
					scope = "user"
				}
				items = append(items, protocol.SoftwareItem{Name: f[0], Version: f[1], Publisher: f[2], Source: "flatpak", Scope: scope})
			}
		} else {
			warns = append(warns, "flatpak: "+err.Error())
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("no supported package manager found")
	}
	return protocol.SoftwareData{Items: items}, warns, nil
}

// ---------------------------------------------------------------------------
// autostart
// ---------------------------------------------------------------------------

var argvRe = regexp.MustCompile(`argv\[\]=([^;]*)`)

func collectAutostartLinux(ctx context.Context, _ *State) (any, []string, error) {
	var items []protocol.AutostartItem
	var warns []string

	// systemd services
	out, err := runCmd(ctx, "systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager")
	if err != nil {
		warns = append(warns, "systemd: "+err.Error())
	} else {
		var units []string
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) > 0 && !strings.Contains(f[0], "@.") {
				units = append(units, f[0])
			}
		}
		if len(units) > 0 {
			show, err := runCmd(ctx, "systemctl", append([]string{"show", "--no-pager", "--property=Id,FragmentPath,ExecStart,Description"}, units...)...)
			if err != nil {
				warns = append(warns, "systemctl show: "+err.Error())
			}
			for _, block := range strings.Split(show, "\n\n") {
				props := map[string]string{}
				for _, l := range strings.Split(block, "\n") {
					k, v, ok := strings.Cut(l, "=")
					if ok {
						props[k] = v
					}
				}
				if props["Id"] == "" {
					continue
				}
				cmd := ""
				if m := argvRe.FindStringSubmatch(props["ExecStart"]); m != nil {
					cmd = strings.TrimSpace(m[1])
				}
				path := props["FragmentPath"]
				vendor := strings.HasPrefix(path, "/usr/lib/systemd/") || strings.HasPrefix(path, "/lib/systemd/")
				items = append(items, protocol.AutostartItem{Name: props["Id"], Command: cmd, Location: "systemd: " + path, Scope: "machine", Enabled: true, Vendor: vendor})
			}
		}
	}

	// cron @reboot
	cronFiles := []string{"/etc/crontab"}
	for _, g := range []string{"/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*"} {
		m, _ := filepath.Glob(g)
		cronFiles = append(cronFiles, m...)
	}
	for _, f := range cronFiles {
		st, err := os.Stat(f)
		if err != nil || st.IsDir() {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if cmd, ok := strings.CutPrefix(l, "@reboot"); ok {
				scope := "machine"
				if strings.Contains(f, "/spool/") {
					scope = "user:" + filepath.Base(f)
				}
				items = append(items, protocol.AutostartItem{Name: "@reboot", Command: strings.TrimSpace(cmd), Location: "cron: " + f, Scope: scope, Enabled: true})
			}
		}
	}

	// XDG autostart (desktop sessions)
	add := func(path, scope string, vendor bool) {
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		kv := map[string]string{}
		for _, l := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(l, "=")
			if ok {
				if _, exists := kv[k]; !exists {
					kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
		}
		enabled := kv["Hidden"] != "true" && kv["X-GNOME-Autostart-enabled"] != "false"
		name := kv["Name"]
		if name == "" {
			name = filepath.Base(path)
		}
		items = append(items, protocol.AutostartItem{Name: name, Command: kv["Exec"], Location: "xdg: " + path, Scope: scope, Enabled: enabled, Vendor: vendor})
	}
	sys, _ := filepath.Glob("/etc/xdg/autostart/*.desktop")
	for _, f := range sys {
		add(f, "machine", true)
	}
	homes, _ := filepath.Glob("/home/*/.config/autostart/*.desktop")
	for _, f := range homes {
		add(f, "user:"+strings.Split(f, "/")[2], false)
	}
	if fileExists("/etc/rc.local") {
		items = append(items, protocol.AutostartItem{Name: "rc.local", Command: "/etc/rc.local", Location: "rc.local", Scope: "machine", Enabled: true})
	}
	return protocol.AutostartData{Items: items}, warns, nil
}

// ---------------------------------------------------------------------------
// events (kernel log)
// ---------------------------------------------------------------------------

var (
	oomRe  = regexp.MustCompile(`Out of memory: Killed process (\d+) \(([^)]+)\)|oom-kill:.*task=([^,]+)`)
	diskRe = []*regexp.Regexp{
		regexp.MustCompile(`(?:I/O|critical medium|critical target) error, dev (\w+)`),
		regexp.MustCompile(`Buffer I/O error on dev(?:ice)? (\w+)`),
		regexp.MustCompile(`EXT4-fs error \(device (\w+)\)`),
		regexp.MustCompile(`EXT4-fs warning \(device (\w+)\): .*I/O error`),
		regexp.MustCompile(`BTRFS (?:error|critical) \(device (\w+)`),
		regexp.MustCompile(`XFS \((\w+)\): (?:.*[Cc]orruption|metadata I/O error)`),
		regexp.MustCompile(`F2FS-fs \((\w+)\): .*(?:error|[Cc]orrupt)`),
		regexp.MustCompile(`(ata\d+)(?:\.\d+)?: (?:failed command|exception Emask)`),
		regexp.MustCompile(`(nvme\d+)\w*: (?:I/O \d+ QID \d+ timeout|controller is down|Device not ready|Removing after probe failure)`),
		regexp.MustCompile(`\[(\w+)\] .*(?:Medium Error|Unrecovered read error)`),
		regexp.MustCompile(`\[(sd\w+)\] tag#\d+ uas_eh_abort_handler`), // USB SSDs (common on the Raspberry Pi)
		// SD cards / eMMC (Raspberry Pi and other boards).
		regexp.MustCompile(`(mmcblk\d+)\w*: error -\d+`),
		regexp.MustCompile(`(mmc\d+): (?:[Tt]imeout waiting for hardware (?:interrupt|cmd interrupt)|Card stuck|cmd ?\d+ (?:timeout|error)|Controller never released|error -\d+ whilst)`),
	}
	ignoreDev = regexp.MustCompile(`^(loop|sr|fd|ram|zram)\d*`)
)

// kmsg is one kernel log line.
type kmsg struct {
	t   time.Time
	msg string
}

// collectEventsLinux scans the kernel log. It merges the systemd journal
// (history across reboots, if persistent) with dmesg (current boot; the
// only source on systems with a volatile journal such as log2ram setups,
// or without journald).
func collectEventsLinux(ctx context.Context, st *State) (any, []string, error) {
	since := st.EventsSince
	if since.IsZero() || time.Since(since) > 31*24*time.Hour {
		since = time.Now().Add(-30 * 24 * time.Hour)
	}
	var recs []kmsg
	var warns []string
	sources := 0
	if hasCmd("journalctl") {
		out, err := runCmd(ctx, "journalctl", "-k", "--no-pager", "-o", "json", "--output-fields=MESSAGE,__REALTIME_TIMESTAMP", "--since", since.Format("2006-01-02 15:04:05"))
		if err == nil {
			recs = append(recs, journalRecords(strings.Split(out, "\n"))...)
			sources++
		} else {
			warns = append(warns, "journal: "+err.Error())
		}
	}
	if d, err := dmesgRecords(ctx); err == nil {
		recs = append(recs, d...)
		sources++
	} else {
		warns = append(warns, "dmesg: "+err.Error())
	}
	if sources == 0 {
		return nil, warns, fmt.Errorf("kernel log not readable (journalctl and dmesg failed)")
	}
	var filtered []kmsg
	for _, r := range recs {
		if !r.t.Before(since) {
			filtered = append(filtered, r)
		}
	}
	return protocol.EventsData{Since: since, Events: parseKernelRecords(filtered)}, warns, nil
}

// dmesgRecords reads the kernel ring buffer of the current boot.
func dmesgRecords(ctx context.Context) ([]kmsg, error) {
	if out, err := runCmd(ctx, "dmesg", "--time-format=iso", "--nopager"); err == nil {
		return parseDmesgISO(out), nil
	}
	// BusyBox and old util-linux: "[   12.345678] message" relative to boot.
	out, err := runCmd(ctx, "dmesg")
	if err != nil {
		return nil, err
	}
	return parseDmesgRaw(out, BootTime()), nil
}

func parseDmesgISO(out string) []kmsg {
	var recs []kmsg
	for _, l := range strings.Split(out, "\n") {
		ts, msg, ok := strings.Cut(l, " ")
		if !ok {
			continue
		}
		t, err := time.Parse("2006-01-02T15:04:05,999999-07:00", ts)
		if err != nil {
			continue
		}
		recs = append(recs, kmsg{t, strings.TrimSpace(msg)})
	}
	return recs
}

var dmesgRawRe = regexp.MustCompile(`^(?:<\d+>)?\[\s*(\d+)\.(\d+)\]\s?(.*)$`)

func parseDmesgRaw(out string, boot time.Time) []kmsg {
	var recs []kmsg
	if boot.IsZero() {
		return nil
	}
	for _, l := range strings.Split(out, "\n") {
		m := dmesgRawRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		sec, _ := strconv.ParseInt(m[1], 10, 64)
		recs = append(recs, kmsg{boot.Add(time.Duration(sec) * time.Second), m[3]})
	}
	return recs
}

func journalRecords(lines []string) []kmsg {
	var recs []kmsg
	for _, l := range lines {
		if l == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(l), &rec) != nil {
			continue
		}
		tsStr, _ := rec["__REALTIME_TIMESTAMP"].(string)
		us, _ := strconv.ParseInt(tsStr, 10, 64)
		recs = append(recs, kmsg{time.UnixMicro(us), journalString(rec["MESSAGE"])})
	}
	return recs
}

// ParseKernelEvents extracts events from journalctl JSON lines.
func ParseKernelEvents(lines []string) []protocol.CriticalEvent {
	return parseKernelRecords(journalRecords(lines))
}

// parseKernelRecords extracts OOM kills and disk errors. The same line seen
// in journal and dmesg is counted once; repeated disk errors of one device
// within a minute are grouped.
func parseKernelRecords(recs []kmsg) []protocol.CriticalEvent {
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].t.Before(recs[j].t) })
	type group struct {
		ev    protocol.CriticalEvent
		count int
	}
	groups := map[string]*group{}
	seenLine := map[string]bool{}
	var order []string
	for _, r := range recs {
		msg, ts := r.msg, r.t
		// journal and dmesg timestamps differ slightly: dedupe per minute and text.
		lineKey := fmt.Sprintf("%d|%s", ts.Unix()/60, msg)
		if seenLine[lineKey] {
			continue
		}
		seenLine[lineKey] = true
		if m := oomRe.FindStringSubmatch(msg); m != nil {
			proc := m[2]
			if proc == "" {
				proc = m[3]
			}
			key := fmt.Sprintf("oom|%d|%s", ts.Unix()/60, proc)
			if _, ok := groups[key]; !ok {
				groups[key] = &group{ev: protocol.CriticalEvent{Kind: protocol.EventOOM, Time: ts, Source: "kernel", Message: truncateStr(msg, 500), Key: key}}
				order = append(order, key)
			}
			continue
		}
		for _, re := range diskRe {
			m := re.FindStringSubmatch(msg)
			if m == nil {
				continue
			}
			dev := m[1]
			if ignoreDev.MatchString(dev) {
				break
			}
			key := fmt.Sprintf("disk|%s|%d", diskGroup(dev), ts.Unix()/60)
			if g, ok := groups[key]; ok {
				g.count++
			} else {
				groups[key] = &group{ev: protocol.CriticalEvent{Kind: protocol.EventDiskError, Time: ts, Source: "kernel", Device: dev, Message: truncateStr(msg, 500), Key: key}, count: 1}
				order = append(order, key)
			}
			break
		}
	}
	var out []protocol.CriticalEvent
	for _, k := range order {
		g := groups[k]
		if g.count > 1 {
			g.ev.Message += fmt.Sprintf(" (+%d similar)", g.count-1)
		}
		out = append(out, g.ev)
	}
	if len(out) > 500 {
		out = out[len(out)-500:]
	}
	return out
}

// diskGroup maps partitions and controllers to their disk so that an error
// burst on one card (mmc0, mmcblk0, mmcblk0p2) forms one event per minute.
var (
	mmcblkRe = regexp.MustCompile(`^mmcblk(\d+)`)
	nvmeRe   = regexp.MustCompile(`^(nvme\d+)`)
)

func diskGroup(dev string) string {
	if m := mmcblkRe.FindStringSubmatch(dev); m != nil {
		return "mmc" + m[1]
	}
	if m := nvmeRe.FindStringSubmatch(dev); m != nil {
		return m[1]
	}
	if strings.HasPrefix(dev, "sd") {
		return strings.TrimRight(dev, "0123456789")
	}
	return dev
}

// journalString decodes MESSAGE, which journald emits as an array of bytes
// when it is not valid UTF-8.
func journalString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		b := make([]byte, 0, len(t))
		for _, x := range t {
			if f, ok := x.(float64); ok {
				b = append(b, byte(f))
			}
		}
		return string(b)
	}
	return ""
}
