package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

// Severities.
const (
	SevWarning  = "warning"
	SevCritical = "critical"
)

// ParamDef describes a numeric rule parameter.
type ParamDef struct {
	Key     string
	Label   string
	Unit    string
	Default float64
}

// RuleDef is an entry of the built-in rule catalog.
type RuleDef struct {
	ID                    string
	Group                 string
	Title                 string
	Description           string
	DefaultEnabled        bool
	DefaultSeverity       string
	Params                []ParamDef
	DiskScope             bool // offers "system disk only"
	ExternalOption        bool // offers "include USB/removable disks"
	DefaultSystemDiskOnly bool
}

// RuleCatalog lists all alert rules.
var RuleCatalog = []RuleDef{
	{ID: "offline", Group: "Agent", Title: "Device offline", Description: "No check-in for longer than the given time. Can be overridden per device.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"hours", "Offline for", "hours", 168}}},
	{ID: "agent_update_failed", Group: "Agent", Title: "Agent update failed", Description: "The agent could not install a new version.",
		DefaultEnabled: true, DefaultSeverity: SevWarning},

	{ID: "smart_failed", Group: "Disks", Title: "SMART health check failed", Description: "The drive reports that it is failing.",
		DefaultEnabled: true, DefaultSeverity: SevCritical, DiskScope: true},
	{ID: "smart_reallocated", Group: "Disks", Title: "Reallocated sectors", Description: "Reallocated sector count above the threshold (ATA).",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"max", "Allowed", "sectors", 0}}},
	{ID: "smart_pending", Group: "Disks", Title: "Pending sectors", Description: "Sectors waiting to be remapped (ATA).",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"max", "Allowed", "sectors", 0}}},
	{ID: "smart_uncorrectable", Group: "Disks", Title: "Uncorrectable errors", Description: "Offline uncorrectable sectors (ATA) or media errors (NVMe).",
		DefaultEnabled: true, DefaultSeverity: SevCritical, DiskScope: true, Params: []ParamDef{{"max", "Allowed", "errors", 0}}},
	{ID: "smart_temperature", Group: "Disks", Title: "Disk temperature", Description: "Drive temperature at or above the threshold.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"celsius", "Threshold", "°C", 65}}},
	{ID: "nvme_wear", Group: "Disks", Title: "SSD wear", Description: "NVMe 'percentage used' or eMMC life time estimate at or above the threshold.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"percent", "Threshold", "%", 90}}},
	{ID: "nvme_critical", Group: "Disks", Title: "NVMe critical warning", Description: "NVMe critical warning flags set or available spare below threshold.",
		DefaultEnabled: true, DefaultSeverity: SevCritical, DiskScope: true},
	{ID: "disk_space", Group: "Disks", Title: "Low disk space", Description: "Free space on a local volume below the threshold.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"percent", "Free below", "%", 10}}},

	{ID: "updates_failed", Group: "Updates", Title: "Update installation failed", Description: "An update failed within the given time and has not been installed successfully since.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"days", "Within", "days", 7}}},
	{ID: "updates_pending", Group: "Updates", Title: "Updates pending too long", Description: "Updates are available for longer than the given time.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"days", "Pending for", "days", 14}}},
	{ID: "update_check_failed", Group: "Updates", Title: "Update check failing", Description: "Searching for updates fails for longer than the given time.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"days", "Failing for", "days", 3}}},
	{ID: "reboot_pending", Group: "Updates", Title: "Reboot pending too long", Description: "A reboot is required for longer than the given time.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"days", "Pending for", "days", 7}}},
	{ID: "os_eol", Group: "Updates", Title: "Operating system end of support", Description: "The OS version is out of support or will be within the given time.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"days", "Warn before", "days", 30}}},
	{ID: "office_eol", Group: "Updates", Title: "Office end of support", Description: "An installed Office, Visio or Project release (perpetual license, e.g. 2016, 2021, LTSC 2024) is out of support or will be within the given time. Microsoft 365 Apps are not affected.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"days", "Warn before", "days", 30}}},

	{ID: "defender_off", Group: "Security", Title: "Defender disabled", Description: "Microsoft Defender antivirus or real-time protection is off (passive mode is ignored).",
		DefaultEnabled: true, DefaultSeverity: SevCritical},
	{ID: "defender_signatures", Group: "Security", Title: "Defender signatures outdated", Description: "Antivirus signatures older than the given age.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"days", "Older than", "days", 7}}},
	{ID: "av_off", Group: "Security", Title: "No active antivirus", Description: "None of the antivirus products registered with the Windows Security Center (Defender or third-party) is active.",
		DefaultEnabled: true, DefaultSeverity: SevCritical},
	{ID: "av_outdated", Group: "Security", Title: "Third-party antivirus outdated", Description: "An active third-party antivirus product reports outdated signatures (Defender has its own rule).",
		DefaultEnabled: true, DefaultSeverity: SevWarning},
	{ID: "firewall_off", Group: "Security", Title: "Firewall disabled", Description: "The firewall is off for a network profile (Windows: domain/private/public; macOS: application firewall). Disable the rule per device where this is intended.",
		DefaultEnabled: true, DefaultSeverity: SevWarning},
	{ID: "malware_active", Group: "Security", Title: "Malware not removed", Description: "Microsoft Defender detected a threat within the given time that was not removed, quarantined or blocked (e.g. allowed or removal failed).",
		DefaultEnabled: true, DefaultSeverity: SevCritical, Params: []ParamDef{{"days", "Within", "days", 30}}},
	{ID: "secureboot_certs", Group: "Security", Title: "Secure Boot 2023 certificates missing", Description: "Secure Boot is enabled but the 'Windows UEFI CA 2023' certificate is not in the UEFI db.",
		DefaultEnabled: true, DefaultSeverity: SevWarning},
	{ID: "not_activated", Group: "Security", Title: "Windows not activated", Description: "Windows reports no valid license.",
		DefaultEnabled: true, DefaultSeverity: SevWarning},
	{ID: "encryption_off", Group: "Security", Title: "System drive not encrypted", Description: "BitLocker / LUKS / FileVault not active on the system volume.",
		DefaultEnabled: false, DefaultSeverity: SevWarning},
	{ID: "battery_health", Group: "Hardware", Title: "Battery worn out", Description: "Battery capacity below the given percentage of its design capacity.",
		DefaultEnabled: false, DefaultSeverity: SevWarning, Params: []ParamDef{{"percent", "Below", "%", 60}}},

	{ID: "bluescreen", Group: "Events", Title: "Bluescreen", Description: "The system crashed (bug check) within the given time.",
		DefaultEnabled: true, DefaultSeverity: SevCritical, Params: []ParamDef{{"hours", "Within", "hours", 24}}},
	{ID: "disk_errors", Group: "Events", ExternalOption: true, Title: "Disk errors in system log", Description: "I/O, SD card/eMMC or file system errors logged within the given time.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"hours", "Within", "hours", 24}, {"min", "At least", "events", 1}}},
	{ID: "undervoltage", Group: "Events", Title: "Undervoltage (Raspberry Pi)", Description: "The power supply voltage dropped too low within the given time, or is too low right now. Undervoltage corrupts SD cards.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"hours", "Within", "hours", 24}}},
	{ID: "malware_detected", Group: "Events", Title: "Malware detected", Description: "Microsoft Defender detected a threat within the given time, also if it was removed.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"hours", "Within", "hours", 336}}},
	{ID: "admin_added", Group: "Events", Title: "New local administrator", Description: "An account was added to the local administrators within the given time.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"hours", "Within", "hours", 168}}},
	{ID: "autostart_added", Group: "Events", Title: "New autostart entry", Description: "A program outside of the OS was added to the autostart (Run keys, services, logon/boot tasks) within the given time. Installers create such entries too.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"hours", "Within", "hours", 168}}},
	{ID: "defender_exclusion_added", Group: "Events", Title: "New Defender exclusion", Description: "A path, file type, process or IP address was excluded from Microsoft Defender scanning within the given time – a common malware technique.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"hours", "Within", "hours", 336}}},
	{ID: "oom", Group: "Events", Title: "Out of memory", Description: "The kernel killed processes because memory ran out (Linux).",
		DefaultEnabled: true, DefaultSeverity: SevWarning, Params: []ParamDef{{"hours", "Within", "hours", 24}}},
}

func ruleDef(id string) *RuleDef {
	for i := range RuleCatalog {
		if RuleCatalog[i].ID == id {
			return &RuleCatalog[i]
		}
	}
	return nil
}

// finding is a condition detected by a rule.
type finding struct {
	Rule     string
	Subject  string
	Severity string
	Message  string
}

func (f finding) key() string { return f.Rule + "\x00" + f.Subject }

// evaluation collects findings and the set of rules that could be evaluated.
// Open alerts of rules that could not be evaluated are left untouched.
type evaluation struct {
	findings  []finding
	evaluated map[string]bool
}

func (e *evaluation) ok(rule string) { e.evaluated[rule] = true }

func (e *evaluation) add(rc RuleConfig, rule, subject, format string, args ...any) {
	e.findings = append(e.findings, finding{Rule: rule, Subject: subject, Severity: rc.Severity, Message: fmt.Sprintf(format, args...)})
}

// evalContext bundles what rules look at.
type evalContext struct {
	now      time.Time
	device   *store.Device
	snaps    map[string]*store.Snapshot
	settings AlertSettings
	srv      *Server
	ctx      context.Context
}

func decodeSnap[T any](snaps map[string]*store.Snapshot, name string) (*T, bool) {
	sn, ok := snaps[name]
	if !ok || sn.Error != "" || len(sn.Data) == 0 {
		return nil, false
	}
	var v T
	if json.Unmarshal(sn.Data, &v) != nil {
		return nil, false
	}
	return &v, true
}

// evaluateDevice runs all enabled rules for a device.
func (s *Server) evaluateDevice(ctx context.Context, d *store.Device, snaps map[string]*store.Snapshot, as AlertSettings, now time.Time) *evaluation {
	ev := &evaluation{evaluated: map[string]bool{}}
	rule := func(id string) (RuleConfig, bool) {
		rc := as.Rules[id]
		if !rc.Enabled || slices.Contains(d.DisabledRules, id) {
			ev.ok(id) // disabled rules resolve their alerts
			return rc, false
		}
		return rc, true
	}
	p := func(rc RuleConfig, key string) float64 { return rc.Params[key] }

	// --- agent ---
	if rc, on := rule("offline"); on {
		hours := p(rc, "hours")
		if d.OfflineAlertHours.Valid {
			hours = float64(d.OfflineAlertHours.Int64)
		}
		ev.ok("offline")
		if hours > 0 && !d.LastSeenAt.IsZero() && now.Sub(d.LastSeenAt) > time.Duration(hours*float64(time.Hour)) {
			ev.add(rc, "offline", "", "No check-in since %s (%s ago).", d.LastSeenAt.Format("2006-01-02 15:04"), humanDuration(now.Sub(d.LastSeenAt)))
		}
	}
	if rc, on := rule("agent_update_failed"); on {
		ev.ok("agent_update_failed")
		if d.UpdateState == updFailed {
			ev.add(rc, "agent_update_failed", "", "Updating the agent to %s failed: %s", d.UpdateTarget, d.UpdateError)
		}
	}

	// --- disks ---
	if smart, ok := decodeSnap[protocol.SmartData](snaps, protocol.CollectSMART); ok {
		for _, id := range []string{"smart_failed", "smart_reallocated", "smart_pending", "smart_uncorrectable", "smart_temperature", "nvme_wear", "nvme_critical"} {
			rc, on := rule(id)
			if !on {
				continue
			}
			ev.ok(id)
			for _, dk := range smart.Disks {
				if rc.SystemDiskOnly && !dk.System {
					continue
				}
				if dk.External && !rc.SystemDiskOnly {
					continue // external disks never alert
				}
				subj := diskSubject(dk)
				name := diskLabel(dk)
				switch id {
				case "smart_failed":
					if dk.HealthPassed != nil && !*dk.HealthPassed {
						ev.add(rc, id, subj, "%s: SMART overall health self-assessment FAILED.", name)
					}
				case "smart_reallocated":
					if dk.Reallocated != nil && float64(*dk.Reallocated) > p(rc, "max") {
						ev.add(rc, id, subj, "%s: %d reallocated sectors.", name, *dk.Reallocated)
					}
				case "smart_pending":
					if dk.Pending != nil && float64(*dk.Pending) > p(rc, "max") {
						ev.add(rc, id, subj, "%s: %d pending sectors.", name, *dk.Pending)
					}
				case "smart_uncorrectable":
					var n int64
					if dk.Uncorrectable != nil {
						n += *dk.Uncorrectable
					}
					if dk.MediaErrors != nil {
						n += *dk.MediaErrors
					}
					if n > 0 && float64(n) > p(rc, "max") {
						ev.add(rc, id, subj, "%s: %d uncorrectable/media errors.", name, n)
					}
				case "smart_temperature":
					if dk.Temperature != nil && float64(*dk.Temperature) >= p(rc, "celsius") {
						ev.add(rc, id, subj, "%s: temperature %d °C.", name, *dk.Temperature)
					}
				case "nvme_wear":
					if dk.PercentUsed != nil && float64(*dk.PercentUsed) >= p(rc, "percent") {
						ev.add(rc, id, subj, "%s: %d%% of rated endurance used.", name, *dk.PercentUsed)
					}
				case "nvme_critical":
					if dk.CriticalWarning != nil && *dk.CriticalWarning != 0 {
						ev.add(rc, id, subj, "%s: NVMe critical warning 0x%02x.", name, *dk.CriticalWarning)
					} else if dk.AvailableSpare != nil && dk.SpareThreshold != nil && *dk.SpareThreshold > 0 && *dk.AvailableSpare <= *dk.SpareThreshold {
						ev.add(rc, id, subj, "%s: available spare %d%% at or below threshold %d%%.", name, *dk.AvailableSpare, *dk.SpareThreshold)
					}
				}
			}
		}
	}

	sys, sysOK := decodeSnap[protocol.SystemInfo](snaps, protocol.CollectSystem)
	if sysOK {
		if rc, on := rule("disk_space"); on {
			ev.ok("disk_space")
			for _, v := range sys.Volumes {
				if v.SizeBytes < 1<<30 { // ignore tiny volumes (EFI, recovery)
					continue
				}
				free := float64(v.FreeBytes) / float64(v.SizeBytes) * 100
				if free < p(rc, "percent") {
					ev.add(rc, "disk_space", v.Mount, "Volume %s: only %.1f%% free (%s of %s).", v.Mount, free, humanBytes(v.FreeBytes), humanBytes(v.SizeBytes))
				}
			}
		}
		sec := sys.Security
		if rc, on := rule("defender_off"); on {
			ev.ok("defender_off")
			if df := sec.Defender; df != nil && df.Present && !strings.Contains(strings.ToLower(df.RunningMode), "passive") {
				if !df.AntivirusEnabled || !df.RealTimeProtection {
					ev.add(rc, "defender_off", "", "Microsoft Defender: antivirus enabled=%v, real-time protection=%v.", df.AntivirusEnabled, df.RealTimeProtection)
				}
			}
		}
		if rc, on := rule("defender_signatures"); on {
			ev.ok("defender_signatures")
			if df := sec.Defender; df != nil && df.Present && df.AntivirusEnabled && !strings.Contains(strings.ToLower(df.RunningMode), "passive") && float64(df.SignatureAgeDays) > p(rc, "days") {
				ev.add(rc, "defender_signatures", "", "Defender signatures are %d days old.", df.SignatureAgeDays)
			}
		}
		if rc, on := rule("av_off"); on && len(sec.Antivirus) > 0 {
			ev.ok("av_off")
			active := false
			var names []string
			for _, a := range sec.Antivirus {
				active = active || a.Enabled
				names = append(names, a.Name)
			}
			if !active {
				ev.add(rc, "av_off", "", "No antivirus product is active (registered: %s).", strings.Join(names, ", "))
			}
		}
		if rc, on := rule("av_outdated"); on && len(sec.Antivirus) > 0 {
			ev.ok("av_outdated")
			for _, a := range sec.Antivirus {
				if a.Enabled && !a.Defender && !a.UpToDate {
					ev.add(rc, "av_outdated", a.Name, "%s reports outdated signatures.", a.Name)
				}
			}
		}
		if rc, on := rule("firewall_off"); on && len(sec.Firewall) > 0 {
			ev.ok("firewall_off")
			for _, f := range sec.Firewall {
				if !f.Enabled {
					msg := "Firewall is off: " + f.Name
					if f.Active {
						msg += " (profile of a connected network)"
					}
					ev.add(rc, "firewall_off", f.Name, "%s.", msg)
				}
			}
		}
		if rc, on := rule("malware_active"); on && sec.Defender != nil && sec.Defender.Present {
			ev.ok("malware_active")
			cut := now.Add(-time.Duration(p(rc, "days") * 24 * float64(time.Hour)))
			for _, det := range sec.Defender.Detections {
				if det.Resolved || (!det.Time.IsZero() && det.Time.Before(cut)) {
					continue
				}
				ev.add(rc, "malware_active", det.ID, "Microsoft Defender: %s – %s (%s).", det.Threat, det.Status, strings.Join(det.Resources, ", "))
			}
		}
		if rc, on := rule("secureboot_certs"); on {
			ev.ok("secureboot_certs")
			if sb := sec.SecureBoot; sb != nil && sb.Enabled && sb.DBHasWindowsUEFICA2023 != nil && !*sb.DBHasWindowsUEFICA2023 {
				msg := "Secure Boot is enabled but 'Windows UEFI CA 2023' is missing in the UEFI db."
				if sb.ServicingStatus != "" {
					msg += " Servicing status: " + sb.ServicingStatus + "."
				}
				ev.add(rc, "secureboot_certs", "", "%s", msg)
			}
		}
		if rc, on := rule("not_activated"); on {
			ev.ok("not_activated")
			if a := sec.Activation; a != nil && !a.Licensed {
				ev.add(rc, "not_activated", "", "Windows license status: %s.", a.Status)
			}
		}
		if rc, on := rule("encryption_off"); on {
			ev.ok("encryption_off")
			for _, v := range sys.Volumes {
				if v.System && v.Encrypted != nil && !*v.Encrypted {
					ev.add(rc, "encryption_off", v.Mount, "System volume %s is not encrypted.", v.Mount)
				}
			}
		}
		if rc, on := rule("battery_health"); on {
			ev.ok("battery_health")
			for i, b := range sys.Battery {
				if b.HealthPercent > 0 && b.HealthPercent < p(rc, "percent") {
					ev.add(rc, "battery_health", fmt.Sprintf("bat%d", i), "Battery %s at %.0f%% of design capacity.", b.Name, b.HealthPercent)
				}
			}
		}
		if rc, on := rule("os_eol"); on {
			if info, known := s.eol.Lookup(sys.OS); known {
				ev.ok("os_eol")
				if !info.EOL.IsZero() {
					left := info.EOL.Sub(now)
					switch {
					case left < 0:
						ev.add(rc, "os_eol", "", "%s is out of support since %s.", info.Label, info.EOL.Format("2006-01-02"))
					case left < time.Duration(p(rc, "days")*24*float64(time.Hour)):
						ev.add(rc, "os_eol", "", "%s goes out of support on %s.", info.Label, info.EOL.Format("2006-01-02"))
					}
				} else if info.IsEOL {
					ev.add(rc, "os_eol", "", "%s is out of support.", info.Label)
				}
			}
		}
	}

	// --- software ---
	if sw, ok := decodeSnap[protocol.SoftwareData](snaps, protocol.CollectSoftware); ok {
		if rc, on := rule("office_eol"); on {
			ev.ok("office_eol")
			for _, o := range s.eol.OfficeLookup(sw.Items) {
				names := strings.Join(o.Products, ", ")
				switch {
				case !o.EOL.IsZero() && o.EOL.Before(now):
					ev.add(rc, "office_eol", o.Cycle, "%s is out of support since %s.", names, o.EOL.Format("2006-01-02"))
				case !o.EOL.IsZero() && o.EOL.Sub(now) < time.Duration(p(rc, "days")*24*float64(time.Hour)):
					ev.add(rc, "office_eol", o.Cycle, "%s goes out of support on %s.", names, o.EOL.Format("2006-01-02"))
				case o.EOL.IsZero() && o.IsEOL:
					ev.add(rc, "office_eol", o.Cycle, "%s is out of support.", names)
				}
			}
		}
	}

	// --- updates ---
	if up, ok := decodeSnap[protocol.UpdatesData](snaps, protocol.CollectUpdates); ok {
		if rc, on := rule("updates_failed"); on {
			ev.ok("updates_failed")
			cut := now.Add(-time.Duration(p(rc, "days") * 24 * float64(time.Hour)))
			latest := map[string]protocol.UpdateHistoryEntry{}
			for _, h := range up.History {
				if cur, ok := latest[h.Title]; !ok || h.Date.After(cur.Date) {
					latest[h.Title] = h
				}
			}
			var failed []string
			for t, h := range latest {
				if (h.Result == "Failed" || h.Result == "Aborted") && h.Date.After(cut) {
					s := t
					if h.HResult != "" {
						s += " (" + h.HResult + ")"
					}
					failed = append(failed, s)
				}
			}
			sort.Strings(failed)
			if len(failed) > 0 {
				ev.add(rc, "updates_failed", "", "%d update(s) failed: %s", len(failed), strings.Join(failed, "; "))
			}
		}
		pendingSince, _ := s.store.SetFlag(ctx, d.ID, "updates_pending", up.PendingCount > 0, now)
		if rc, on := rule("updates_pending"); on {
			ev.ok("updates_pending")
			if up.PendingCount > 0 && now.Sub(pendingSince) > time.Duration(p(rc, "days")*24*float64(time.Hour)) {
				ev.add(rc, "updates_pending", "", "%d update(s) pending since %s.", up.PendingCount, pendingSince.Format("2006-01-02"))
			}
		}
		errSince, _ := s.store.SetFlag(ctx, d.ID, "update_check_failed", up.SearchError != "", now)
		if rc, on := rule("update_check_failed"); on {
			ev.ok("update_check_failed")
			if up.SearchError != "" && now.Sub(errSince) > time.Duration(p(rc, "days")*24*float64(time.Hour)) {
				ev.add(rc, "update_check_failed", "", "Update search failing since %s: %s", errSince.Format("2006-01-02"), up.SearchError)
			}
		}
		rebootSince, _ := s.store.SetFlag(ctx, d.ID, "reboot_pending", up.RebootRequired, now)
		if rc, on := rule("reboot_pending"); on {
			ev.ok("reboot_pending")
			if up.RebootRequired && now.Sub(rebootSince) > time.Duration(p(rc, "days")*24*float64(time.Hour)) {
				ev.add(rc, "reboot_pending", "", "Reboot required since %s.", rebootSince.Format("2006-01-02"))
			}
		}
	}

	// --- events ---
	for _, it := range []struct {
		rule, kind, label string
		details           bool // list the event messages
	}{
		{"bluescreen", protocol.EventBluescreen, "bluescreen(s)", false},
		{"disk_errors", protocol.EventDiskError, "disk error event(s)", false},
		{"oom", protocol.EventOOM, "out-of-memory kill(s)", false},
		{"undervoltage", protocol.EventUndervoltage, "undervoltage event(s)", false},
		{"malware_detected", protocol.EventMalware, "malware detection(s)", true},
		{"admin_added", protocol.EventAdminAdded, "new local administrator(s)", true},
		{"autostart_added", protocol.EventAutostartAdded, "new autostart entry/entries", true},
		{"defender_exclusion_added", protocol.EventDefenderExclusion, "new Defender exclusion(s)", true},
	} {
		rc, on := rule(it.rule)
		if !on {
			continue
		}
		hours := p(rc, "hours")
		n, err := s.store.CountEvents(ctx, d.ID, it.kind, now.Add(-time.Duration(hours*float64(time.Hour))), rc.IncludeExternal)
		if err != nil {
			continue
		}
		ev.ok(it.rule)
		min := p(rc, "min")
		if min < 1 {
			min = 1
		}
		switch {
		case float64(n) >= min:
			msg := fmt.Sprintf("%d %s in the last %.0f hours.", n, it.label, hours)
			if it.details {
				msg += eventDetails(ctx, s.store, d.ID, it.kind, now.Add(-time.Duration(hours*float64(time.Hour))))
			}
			if it.rule == "undervoltage" && sysOK && sys.PiPower != nil && sys.PiPower.UndervoltageNow {
				msg += " Undervoltage is present right now."
			}
			ev.add(rc, it.rule, "", "%s", msg)
		case it.rule == "undervoltage" && sysOK && sys.PiPower != nil && sys.PiPower.UndervoltageNow:
			ev.add(rc, it.rule, "", "Undervoltage is present right now (%s). Check the power supply and cable.", sys.PiPower.Source)
		}
	}
	return ev
}

func diskSubject(d protocol.Disk) string {
	if d.Serial != "" {
		return d.Serial
	}
	return d.Device
}

func diskLabel(d protocol.Disk) string {
	l := d.Model
	if l == "" {
		l = d.Device
	}
	if d.System {
		l += " (system disk)"
	}
	return l
}

// ---------------------------------------------------------------------------
// reconciliation and notification
// ---------------------------------------------------------------------------

func (s *Server) kickAlerts(deviceID string) {
	select {
	case s.alertKick <- deviceID:
	default:
	}
}

func (s *Server) alertLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	// Initial full run shortly after start.
	initial := time.After(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-s.alertKick:
			// Debounce: collect kicks for a moment.
			ids := map[string]bool{id: true}
			deadline := time.After(3 * time.Second)
		collect:
			for {
				select {
				case id := <-s.alertKick:
					ids[id] = true
				case <-deadline:
					break collect
				case <-ctx.Done():
					return
				}
			}
			s.runAlerts(ctx, ids)
		case <-initial:
			s.runAlerts(ctx, nil)
		case <-t.C:
			s.runAlerts(ctx, nil)
		}
	}
}

// runAlerts evaluates the given devices (nil = all) and sends notifications.
func (s *Server) runAlerts(ctx context.Context, only map[string]bool) {
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		s.log.Error("alerts: list devices", "err", err)
		return
	}
	as := s.alertSettings(ctx)
	now := time.Now()
	for i := range devices {
		d := &devices[i]
		if only != nil && !only[d.ID] && !only[""] {
			continue
		}
		if !d.RevokedAt.IsZero() {
			continue
		}
		snaps, err := s.store.Snapshots(ctx, d.ID)
		if err != nil {
			continue
		}
		ev := s.evaluateDevice(ctx, d, snaps, as, now)
		opened, resolved, renotify := s.reconcile(ctx, d, ev, as, now)
		if d.AlertsMuted {
			continue
		}
		if len(opened)+len(resolved)+len(renotify) > 0 {
			s.notifyDevice(ctx, d, as, opened, resolved, renotify, now)
		}
	}
}

func (s *Server) reconcile(ctx context.Context, d *store.Device, ev *evaluation, as AlertSettings, now time.Time) (opened, resolved, renotify []store.Alert) {
	open, err := s.store.OpenAlertsForDevice(ctx, d.ID)
	if err != nil {
		return
	}
	cur := map[string]finding{}
	for _, f := range ev.findings {
		cur[f.key()] = f
	}
	existing := map[string]store.Alert{}
	for _, a := range open {
		existing[a.Rule+"\x00"+a.Subject] = a
	}
	for k, f := range cur {
		if a, ok := existing[k]; ok {
			if a.Severity != f.Severity || a.Message != f.Message || now.Sub(a.LastSeenAt) > time.Hour {
				_ = s.store.TouchAlert(ctx, a.ID, f.Severity, f.Message, now)
			}
			a.Severity, a.Message = f.Severity, f.Message
			if as.RenotifyHours > 0 && !a.LastNotifiedAt.IsZero() && now.Sub(a.LastNotifiedAt) > time.Duration(as.RenotifyHours)*time.Hour {
				renotify = append(renotify, a)
			} else if a.LastNotifiedAt.IsZero() && !d.AlertsMuted {
				// Never notified (e.g. SMTP was not configured): try again.
				renotify = append(renotify, a)
			}
			continue
		}
		a := store.Alert{DeviceID: d.ID, Rule: f.Rule, Subject: f.Subject, Severity: f.Severity, Message: f.Message, OpenedAt: now, LastSeenAt: now}
		if err := s.store.InsertAlert(ctx, &a); err != nil {
			s.log.Warn("insert alert", "err", err)
			continue
		}
		opened = append(opened, a)
	}
	for k, a := range existing {
		if _, still := cur[k]; still {
			continue
		}
		if !ev.evaluated[a.Rule] {
			continue // no fresh data for this rule: keep the alert
		}
		_ = s.store.ResolveAlert(ctx, a.ID, now)
		a.ResolvedAt = now
		if !a.LastNotifiedAt.IsZero() {
			resolved = append(resolved, a)
		}
	}
	return
}

func (s *Server) notifyDevice(ctx context.Context, d *store.Device, as AlertSettings, opened, resolved, renotify []store.Alert, now time.Time) {
	smtp := s.smtpSettings(ctx)
	if !smtp.Configured() {
		return
	}
	// Group alerts by recipient list.
	type batch struct {
		to                         []string
		opened, resolved, renotify []store.Alert
	}
	batches := map[string]*batch{}
	// The recipients of the device's area get its alerts in addition to the
	// global (or rule specific) recipients.
	var areaTo []string
	if area, err := s.store.AreaByID(ctx, d.AreaID); err == nil {
		areaTo = area.Recipients
	}
	add := func(a store.Alert, kind string) {
		to := as.Recipients
		if rc, ok := as.Rules[a.Rule]; ok && len(rc.Recipients) > 0 {
			to = rc.Recipients
		}
		to = mergeRecipients(to, areaTo)
		if len(to) == 0 {
			return
		}
		key := strings.Join(to, ",")
		b := batches[key]
		if b == nil {
			b = &batch{to: to}
			batches[key] = b
		}
		switch kind {
		case "opened":
			b.opened = append(b.opened, a)
		case "resolved":
			if as.NotifyResolved {
				b.resolved = append(b.resolved, a)
			}
		case "renotify":
			b.renotify = append(b.renotify, a)
		}
	}
	for _, a := range opened {
		add(a, "opened")
	}
	for _, a := range resolved {
		add(a, "resolved")
	}
	for _, a := range renotify {
		add(a, "renotify")
	}
	for _, b := range batches {
		if len(b.opened)+len(b.resolved)+len(b.renotify) == 0 {
			continue
		}
		subject, body := s.alertMail(ctx, d, b.opened, b.resolved, b.renotify)
		if err := s.mailer.Send(ctx, b.to, subject, body); err != nil {
			s.log.Warn("sending alert mail failed", "device", d.ID, "err", err)
			continue
		}
		for _, a := range append(append(b.opened, b.renotify...), b.resolved...) {
			_ = s.store.MarkAlertNotified(ctx, a.ID, now)
		}
	}
}

// mergeRecipients joins recipient lists without duplicates (case insensitive).
func mergeRecipients(lists ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range lists {
		for _, r := range l {
			k := strings.ToLower(strings.TrimSpace(r))
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, strings.TrimSpace(r))
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) alertMail(ctx context.Context, d *store.Device, opened, resolved, renotify []store.Alert) (string, string) {
	g := s.generalSettings(ctx)
	sev := ""
	for _, a := range append(opened, renotify...) {
		if a.Severity == SevCritical {
			sev = "CRITICAL"
			break
		}
		sev = "WARNING"
	}
	var subj string
	switch {
	case len(opened)+len(renotify) > 0:
		first := append(opened, renotify...)[0]
		title := first.Rule
		if def := ruleDef(first.Rule); def != nil {
			title = def.Title
		}
		subj = fmt.Sprintf("[%s] %s: %s: %s", g.InstanceName, sev, d.Name(), title)
		if n := len(opened) + len(renotify); n > 1 {
			subj += fmt.Sprintf(" (+%d more)", n-1)
		}
	default:
		subj = fmt.Sprintf("[%s] RESOLVED: %s (%d alert(s))", g.InstanceName, d.Name(), len(resolved))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Device: %s\n", d.Name())
	if d.OSName != "" {
		fmt.Fprintf(&b, "OS:     %s\n", d.OSName)
	}
	if !d.LastSeenAt.IsZero() {
		fmt.Fprintf(&b, "Seen:   %s\n", d.LastSeenAt.Format("2006-01-02 15:04 MST"))
	}
	b.WriteString("\n")
	section := func(title string, list []store.Alert) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s\n%s\n", title, strings.Repeat("-", len(title)))
		for _, a := range list {
			name := a.Rule
			if def := ruleDef(a.Rule); def != nil {
				name = def.Title
			}
			fmt.Fprintf(&b, "* [%s] %s\n  %s\n  since %s\n", strings.ToUpper(a.Severity), name, a.Message, a.OpenedAt.Format("2006-01-02 15:04"))
		}
		b.WriteString("\n")
	}
	section("New alerts", opened)
	section("Still open", renotify)
	section("Resolved", resolved)
	if base := s.cfg.BaseURL; base != "" {
		fmt.Fprintf(&b, "Details: %s/devices/%s\n", base, d.ID)
	}
	return subj, b.String()
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// eventDetails lists up to three event messages of a kind since t.
func eventDetails(ctx context.Context, st *store.Store, deviceID, kind string, since time.Time) string {
	evs, err := st.Events(ctx, deviceID, since, 500)
	if err != nil {
		return ""
	}
	var msgs []string
	more := 0
	for _, e := range evs {
		if e.Kind != kind {
			continue
		}
		if len(msgs) == 3 {
			more++
			continue
		}
		msgs = append(msgs, e.Message)
	}
	out := ""
	if len(msgs) > 0 {
		out = " " + strings.Join(msgs, " · ")
	}
	if more > 0 {
		out += fmt.Sprintf(" (+%d more)", more)
	}
	return out
}
