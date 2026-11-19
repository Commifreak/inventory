package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
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
	{ID: "smart_reallocated", Group: "Disks", Title: "Reallocated sectors", Description: "Reallocated sector count above the threshold (ATA) and grown within the given time – or the disk was first reported with it. A count that stays the same does not alert again.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"max", "Allowed", "sectors", 0}, {"days", "New within", "days", 7}}},
	{ID: "smart_pending", Group: "Disks", Title: "Pending sectors", Description: "Sectors waiting to be remapped (ATA).",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"max", "Allowed", "sectors", 0}}},
	{ID: "smart_uncorrectable", Group: "Disks", Title: "Uncorrectable errors", Description: "Offline uncorrectable sectors (ATA).",
		DefaultEnabled: true, DefaultSeverity: SevCritical, DiskScope: true, Params: []ParamDef{{"max", "Allowed", "errors", 0}}},
	{ID: "nvme_media_errors", Group: "Disks", Title: "NVMe media errors", Description: "Unrecovered data integrity errors of an NVMe drive, grown within the given time – or the drive was first reported with them. A count that stays the same does not alert again.",
		DefaultEnabled: true, DefaultSeverity: SevCritical, DiskScope: true, Params: []ParamDef{{"days", "New within", "days", 7}}},
	{ID: "smart_error_counters", Group: "Disks", Title: "Disk error counters increasing", Description: "Early signs of a failing disk: reported uncorrectable errors (187), command timeouts (188) or spin retries (10) grew within the given time. Uncorrectable errors and spin retries also alert once when the disk is first reported with them.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"days", "Within", "days", 7}}},
	{ID: "smart_crc", Group: "Disks", Title: "Interface CRC errors increasing", Description: "The interface CRC error count (ATA attribute 199) grew within the given time – usually a bad cable, connector or slot rather than the disk itself. Errors counted before do not alert.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"days", "Within", "days", 7}}},
	{ID: "power_loss", Group: "Disks", Title: "Unexpected power losses increasing", Description: "The disk counted unexpected power losses (NVMe unsafe shutdowns, ATA 174/192) within the given time – power cuts, a failing power supply or a device switched off hard. Earlier counts do not alert.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"days", "Within", "days", 7}, {"min", "At least", "power losses", 3}}},
	{ID: "smart_temperature", Group: "Disks", Title: "Disk temperature", Description: "Drive temperature at or above the threshold.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"celsius", "Threshold", "°C", 65}}},
	{ID: "nvme_wear", Group: "Disks", Title: "SSD wear", Description: "Used endurance of an SSD (NVMe 'percentage used', SATA/SAS endurance indicator or wear attributes) or eMMC life time estimate at or above the threshold. No reminders – another mail every further 10 percentage points.",
		DefaultEnabled: true, DefaultSeverity: SevWarning, DiskScope: true, Params: []ParamDef{{"percent", "Threshold", "%", 90}}},
	{ID: "nvme_critical", Group: "Disks", Title: "SSD critical warning", Description: "NVMe critical warning flags set, or the available spare (reserve blocks) of an NVMe/SATA SSD at or below the vendor threshold.",
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
	event    *eventSpec // set for findings of event rules
	level    *levelSpec // set for step-notified findings
}

// levelSpec describes a finding of a value that only grows and cannot be
// fixed (SSD wear). Such alerts get no reminders; they are mailed again when
// the value reaches the next step (base + n*step).
type levelSpec struct {
	value, base, step float64
	unit              string
}

func (l *levelSpec) mark(v float64) float64 { return math.Floor((v - l.base) / l.step) }

// eventSpec describes the events behind a finding of an event rule. Such
// alerts are not repeated as reminders – the events are in the past and the
// alert closes when they leave the rule's time window – but events received
// after the last notification are mailed.
type eventSpec struct {
	kind, label string
	since       time.Time // start of the rule's time window
	external    bool      // include events on external disks
	details     bool      // list the event messages
	total       int       // events within the window
	hours       float64
}

// alertChanges are the alerts of a device to notify about.
type alertChanges struct {
	opened, resolved, renotify []store.Alert
	// updated are open event alerts with new events; their Message lists
	// only the events received since the last notification.
	updated []store.Alert
	// increased are step-notified alerts whose value reached the next step.
	increased []store.Alert
	// levels holds the current value of step-notified alerts (by alert ID),
	// stored once they are notified.
	levels map[int64]float64
}

func (c alertChanges) empty() bool {
	return len(c.opened)+len(c.resolved)+len(c.renotify)+len(c.updated)+len(c.increased) == 0
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
		for _, id := range []string{"smart_failed", "smart_pending", "smart_uncorrectable", "smart_temperature", "nvme_wear", "nvme_critical"} {
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
				case "smart_pending":
					if dk.Pending != nil && float64(*dk.Pending) > p(rc, "max") {
						ev.add(rc, id, subj, "%s: %d pending sectors.", name, *dk.Pending)
					}
				case "smart_uncorrectable":
					if dk.Uncorrectable != nil && *dk.Uncorrectable > 0 && float64(*dk.Uncorrectable) > p(rc, "max") {
						ev.add(rc, id, subj, "%s: %d offline uncorrectable sectors.", name, *dk.Uncorrectable)
					}
				case "smart_temperature":
					if dk.Temperature != nil && float64(*dk.Temperature) >= p(rc, "celsius") {
						ev.add(rc, id, subj, "%s: temperature %d °C.", name, *dk.Temperature)
					}
				case "nvme_wear":
					if dk.PercentUsed != nil && float64(*dk.PercentUsed) >= p(rc, "percent") {
						msg := fmt.Sprintf("%s: %d%% of rated endurance used", name, *dk.PercentUsed)
						if *dk.PercentUsed > 100 {
							msg += " – beyond the manufacturer's rating"
							if !diskErrors(dk) {
								msg += ", no errors reported so far"
							}
						}
						ev.add(rc, id, subj, "%s.", msg)
						ev.findings[len(ev.findings)-1].level = &levelSpec{value: float64(*dk.PercentUsed), base: p(rc, "percent"), step: 10, unit: "%"}
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

	// Lifetime counters: alert when they grow, compared with the SMART history.
	if smart, ok := decodeSnap[protocol.SmartData](snaps, protocol.CollectSMART); ok {
		// Reallocated sectors and media errors: new ones, or a disk first
		// reported with them; a stable old count does not alert forever.
		newOrFirst := func(dk protocol.Disk, rc RuleConfig, cur, grew int64, fresh bool) string {
			switch {
			case grew > 0:
				return fmt.Sprintf("%d new in the last %.0f days (%d in total)", grew, p(rc, "days"), cur)
			case fresh:
				return fmt.Sprintf("%d (disk first reported within the last %.0f days)", cur, p(rc, "days"))
			}
			return ""
		}
		s.evalCounter(ctx, ev, rule, d, smart.Disks, now, "smart_reallocated",
			func(dk protocol.Disk) *int64 { return dk.Reallocated },
			func(h store.SmartPoint) *int64 { return h.Reallocated },
			func(dk protocol.Disk, rc RuleConfig, cur, grew int64, fresh bool) string {
				if float64(cur) <= p(rc, "max") {
					return ""
				}
				if m := newOrFirst(dk, rc, cur, grew, fresh); m != "" {
					return fmt.Sprintf("%s: reallocated sectors: %s.", diskLabel(dk), m)
				}
				return ""
			})
		s.evalCounter(ctx, ev, rule, d, smart.Disks, now, "nvme_media_errors",
			func(dk protocol.Disk) *int64 { return dk.MediaErrors },
			func(h store.SmartPoint) *int64 { return h.MediaErrors },
			func(dk protocol.Disk, rc RuleConfig, cur, grew int64, fresh bool) string {
				if cur <= 0 {
					return ""
				}
				if m := newOrFirst(dk, rc, cur, grew, fresh); m != "" {
					return fmt.Sprintf("%s: media errors: %s.", diskLabel(dk), m)
				}
				return ""
			})
		s.evalCounter(ctx, ev, rule, d, smart.Disks, now, "smart_crc",
			func(dk protocol.Disk) *int64 { return dk.CRCErrors },
			func(h store.SmartPoint) *int64 { return h.CRCErrors },
			func(dk protocol.Disk, rc RuleConfig, cur, grew int64, _ bool) string {
				if grew <= 0 {
					return ""
				}
				return fmt.Sprintf("%s: %d new interface CRC error(s) in the last %.0f days (%d in total). Check the cable/connector.", diskLabel(dk), grew, p(rc, "days"), cur)
			})
		s.evalErrorCounters(ctx, ev, rule, d, smart.Disks, now)
		s.evalCounter(ctx, ev, rule, d, smart.Disks, now, "power_loss",
			func(dk protocol.Disk) *int64 { return dk.UnsafeShutdowns },
			func(h store.SmartPoint) *int64 { return h.UnsafeShutdowns },
			func(dk protocol.Disk, rc RuleConfig, cur, grew int64, _ bool) string {
				if grew <= 0 || float64(grew) < p(rc, "min") {
					return ""
				}
				return fmt.Sprintf("%s: %d unexpected power loss(es) in the last %.0f days (%d in total). Check the power supply, or the device was switched off hard.", diskLabel(dk), grew, p(rc, "days"), cur)
			})
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
		since := now.Add(-time.Duration(hours * float64(time.Hour)))
		n, err := s.store.CountEvents(ctx, d.ID, it.kind, since, rc.IncludeExternal)
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
				msg += eventDetails(ctx, s.store, d.ID, it.kind, since, rc.IncludeExternal)
			}
			if it.rule == "undervoltage" && sysOK && sys.PiPower != nil && sys.PiPower.UndervoltageNow {
				msg += " Undervoltage is present right now."
			}
			ev.add(rc, it.rule, "", "%s", msg)
			ev.findings[len(ev.findings)-1].event = &eventSpec{kind: it.kind, label: it.label, since: since,
				external: rc.IncludeExternal, details: it.details, total: n, hours: hours}
		case it.rule == "undervoltage" && sysOK && sys.PiPower != nil && sys.PiPower.UndervoltageNow:
			ev.add(rc, it.rule, "", "Undervoltage is present right now (%s). Check the power supply and cable.", sys.PiPower.Source)
		}
	}
	return ev
}

// evalCounter evaluates a rule on a lifetime SMART counter of every disk.
// msg gets the current value, its growth within the rule's "days" and
// whether the disk was first reported within that period; it returns the
// alert message or "" for no alert. If the history cannot be read, the rule
// counts as not evaluated, so open alerts are kept.
func (s *Server) evalCounter(ctx context.Context, ev *evaluation, rule func(string) (RuleConfig, bool), d *store.Device, disks []protocol.Disk, now time.Time,
	id string, value func(protocol.Disk) *int64, pick func(store.SmartPoint) *int64, msg func(dk protocol.Disk, rc RuleConfig, cur, grew int64, fresh bool) string) {
	rc, on := rule(id)
	if !on {
		return
	}
	since := now.Add(-time.Duration(rc.Params["days"] * 24 * float64(time.Hour)))
	var found []finding
	for _, dk := range disks {
		cur := value(dk)
		if cur == nil || dk.Serial == "" || (rc.SystemDiskOnly && !dk.System) || (dk.External && !rc.SystemDiskOnly) {
			continue
		}
		grew, fresh, err := s.counterChange(ctx, d.ID, dk.Serial, since, *cur, pick)
		if err != nil {
			return
		}
		if m := msg(dk, rc, *cur, grew, fresh); m != "" {
			found = append(found, finding{Rule: id, Subject: diskSubject(dk), Severity: rc.Severity, Message: m})
		}
	}
	ev.ok(id)
	ev.findings = append(ev.findings, found...)
}

// evalErrorCounters evaluates "smart_error_counters": one finding per disk
// listing the counters that grew. Command timeouts only count when they grow
// (many healthy Seagate disks report packed non-zero values).
func (s *Server) evalErrorCounters(ctx context.Context, ev *evaluation, rule func(string) (RuleConfig, bool), d *store.Device, disks []protocol.Disk, now time.Time) {
	rc, on := rule("smart_error_counters")
	if !on {
		return
	}
	days := rc.Params["days"]
	since := now.Add(-time.Duration(days * 24 * float64(time.Hour)))
	counters := []struct {
		label     string
		value     func(protocol.Disk) *int64
		pick      func(store.SmartPoint) *int64
		firstSeen bool // alert once for a disk first reported with a non-zero count
		showCount bool
	}{
		{"reported uncorrectable errors", func(dk protocol.Disk) *int64 { return dk.ReportedUncorrect }, func(h store.SmartPoint) *int64 { return h.ReportedUncorrect }, true, true},
		{"spin retries", func(dk protocol.Disk) *int64 { return dk.SpinRetry }, func(h store.SmartPoint) *int64 { return h.SpinRetry }, true, true},
		{"command timeouts", func(dk protocol.Disk) *int64 { return dk.CommandTimeout }, func(h store.SmartPoint) *int64 { return h.CommandTimeout }, false, false},
	}
	var found []finding
	for _, dk := range disks {
		if dk.Serial == "" || (rc.SystemDiskOnly && !dk.System) || (dk.External && !rc.SystemDiskOnly) {
			continue
		}
		var parts []string
		for _, c := range counters {
			cur := c.value(dk)
			if cur == nil || *cur <= 0 {
				continue
			}
			grew, fresh, err := s.counterChange(ctx, d.ID, dk.Serial, since, *cur, c.pick)
			if err != nil {
				return // not evaluated: open alerts are kept
			}
			switch {
			case grew > 0 && c.showCount:
				parts = append(parts, fmt.Sprintf("%d new %s (%d in total)", grew, c.label, *cur))
			case grew > 0:
				parts = append(parts, c.label+" increased")
			case fresh && c.firstSeen:
				parts = append(parts, fmt.Sprintf("%d %s", *cur, c.label))
			}
		}
		if len(parts) > 0 {
			found = append(found, finding{Rule: "smart_error_counters", Subject: diskSubject(dk), Severity: rc.Severity,
				Message: fmt.Sprintf("%s: %s within the last %.0f days.", diskLabel(dk), strings.Join(parts, ", "), days)})
		}
	}
	ev.ok("smart_error_counters")
	ev.findings = append(ev.findings, found...)
}

// counterChange compares a lifetime counter with the SMART history (one
// value per disk and day, the day's latest): grew is the increase over the
// lowest value since `since`, including the last value before it (the value
// at the start of the period); fresh means the disk has no history before
// `since`.
func (s *Server) counterChange(ctx context.Context, deviceID, serial string, since time.Time, cur int64, pick func(store.SmartPoint) *int64) (grew int64, fresh bool, err error) {
	hist, err := s.store.SmartHistory(ctx, deviceID, serial, time.Time{})
	if err != nil {
		return 0, false, err
	}
	fresh, low := true, cur
	var before *int64
	for _, h := range hist {
		v := pick(h)
		if h.Time.Before(since) {
			fresh = false
			if v != nil {
				before = v
			}
			continue
		}
		if v != nil && *v < low {
			low = *v
		}
	}
	if before != nil && *before < low {
		low = *before
	}
	return cur - low, fresh, nil
}

// diskErrors reports whether a disk has reallocated, pending or
// uncorrectable sectors or media errors.
func diskErrors(d protocol.Disk) bool {
	for _, v := range []*int64{d.Reallocated, d.Pending, d.Uncorrectable, d.ReportedUncorrect, d.MediaErrors} {
		if v != nil && *v > 0 {
			return true
		}
	}
	return d.HealthPassed != nil && !*d.HealthPassed
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
		ch := s.reconcile(ctx, d, ev, as, now)
		if d.AlertsMuted {
			continue
		}
		if !ch.empty() {
			s.notifyDevice(ctx, d, as, ch, now)
		}
	}
}

func (s *Server) reconcile(ctx context.Context, d *store.Device, ev *evaluation, as AlertSettings, now time.Time) (ch alertChanges) {
	open, err := s.store.OpenAlertsForDevice(ctx, d.ID)
	if err != nil {
		return
	}
	ch.levels = map[int64]float64{}
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
			if f.level != nil {
				ch.levels[a.ID] = f.level.value
			}
			switch {
			case a.LastNotifiedAt.IsZero():
				// Never notified (e.g. SMTP was not configured): try again.
				if !d.AlertsMuted {
					ch.renotify = append(ch.renotify, a)
				}
			case f.level != nil:
				// No reminders, a mail per step instead.
				if a.NotifiedValue == nil {
					// Notified before values were recorded: start from now.
					_ = s.store.SetAlertNotifiedValue(ctx, a.ID, f.level.value)
				} else if f.level.mark(f.level.value) > f.level.mark(*a.NotifiedValue) {
					a.Message += fmt.Sprintf(" Previously notified at %s%s.", strconv.FormatFloat(*a.NotifiedValue, 'f', -1, 64), f.level.unit)
					ch.increased = append(ch.increased, a)
				}
			case f.event != nil:
				// Event alerts get no reminders, only their new events.
				if msg := s.newEventsMessage(ctx, d.ID, f.event, a.LastNotifiedAt); msg != "" {
					a.Message = msg
					ch.updated = append(ch.updated, a)
				}
			case as.RenotifyHours > 0 && now.Sub(a.LastNotifiedAt) > time.Duration(as.RenotifyHours)*time.Hour:
				ch.renotify = append(ch.renotify, a)
			}
			continue
		}
		a := store.Alert{DeviceID: d.ID, Rule: f.Rule, Subject: f.Subject, Severity: f.Severity, Message: f.Message, OpenedAt: now, LastSeenAt: now}
		if err := s.store.InsertAlert(ctx, &a); err != nil {
			s.log.Warn("insert alert", "err", err)
			continue
		}
		if f.level != nil {
			ch.levels[a.ID] = f.level.value
		}
		ch.opened = append(ch.opened, a)
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
			ch.resolved = append(ch.resolved, a)
		}
	}
	return
}

// newEventsMessage describes the events of an open event alert that were
// received after its last notification ("" = none).
func (s *Server) newEventsMessage(ctx context.Context, deviceID string, e *eventSpec, notified time.Time) string {
	evs, err := s.store.EventsReceivedAfter(ctx, deviceID, e.kind, e.since, notified, e.external)
	if err != nil || len(evs) == 0 {
		return ""
	}
	msg := fmt.Sprintf("Since the last notification: %d %s.", len(evs), e.label)
	if e.details {
		msgs := make([]string, len(evs))
		for i, ev := range evs {
			msgs[i] = ev.Message
		}
		msg += joinEventMessages(msgs)
	}
	return msg + fmt.Sprintf(" %d in the last %.0f hours in total.", e.total, e.hours)
}

func (s *Server) notifyDevice(ctx context.Context, d *store.Device, as AlertSettings, ch alertChanges, now time.Time) {
	smtp := s.smtpSettings(ctx)
	if !smtp.Configured() {
		return
	}
	// Group alerts by recipient list.
	type batch struct {
		to []string
		alertChanges
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
		case "updated":
			b.updated = append(b.updated, a)
		case "increased":
			b.increased = append(b.increased, a)
		}
	}
	for _, a := range ch.opened {
		add(a, "opened")
	}
	for _, a := range ch.resolved {
		add(a, "resolved")
	}
	for _, a := range ch.renotify {
		add(a, "renotify")
	}
	for _, a := range ch.updated {
		add(a, "updated")
	}
	for _, a := range ch.increased {
		add(a, "increased")
	}
	for _, b := range batches {
		if b.empty() {
			continue
		}
		if err := s.mailer.Send(ctx, b.to, s.alertMail(ctx, d, b.alertChanges)); err != nil {
			s.log.Warn("sending alert mail failed", "device", d.ID, "err", err)
			continue
		}
		for _, a := range slices.Concat(b.opened, b.updated, b.increased, b.renotify, b.resolved) {
			_ = s.store.MarkAlertNotified(ctx, a.ID, now)
			if v, ok := ch.levels[a.ID]; ok && a.ResolvedAt.IsZero() {
				_ = s.store.SetAlertNotifiedValue(ctx, a.ID, v)
			}
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

func (s *Server) alertMail(ctx context.Context, d *store.Device, ch alertChanges) Mail {
	opened, resolved, renotify, updated, increased := ch.opened, ch.resolved, ch.renotify, ch.updated, ch.increased
	g := s.generalSettings(ctx)
	title := func(a store.Alert) string {
		if def := ruleDef(a.Rule); def != nil {
			return def.Title
		}
		return a.Rule
	}
	active := slices.Concat(opened, updated, increased, renotify)
	sev := SevWarning
	for _, a := range active {
		if a.Severity == SevCritical {
			sev = SevCritical
		}
	}
	var subj, heading string
	switch {
	case len(active) > 0:
		subj = fmt.Sprintf("[%s] %s: %s: %s", g.InstanceName, strings.ToUpper(sev), d.Name(), title(active[0]))
		if n := len(active); n > 1 {
			subj += fmt.Sprintf(" (+%d more)", n-1)
		}
		switch {
		case len(opened) == 1 && len(renotify)+len(updated)+len(increased) == 0:
			heading = "New alert"
		case len(opened) > 0:
			heading = fmt.Sprintf("%d new alerts", len(opened))
		case len(updated) > 0:
			heading = "New events"
			if len(updated) > 1 {
				heading = fmt.Sprintf("New events for %d alerts", len(updated))
			}
		case len(increased) > 0:
			heading = "Alert increased"
			if len(increased) > 1 {
				heading = fmt.Sprintf("%d alerts increased", len(increased))
			}
		default:
			heading = fmt.Sprintf("%d alert(s) still open", len(renotify))
		}
		if len(resolved) > 0 {
			heading += fmt.Sprintf(", %d resolved", len(resolved))
		}
	default:
		sev = "resolved"
		subj = fmt.Sprintf("[%s] RESOLVED: %s: %s", g.InstanceName, d.Name(), title(resolved[0]))
		if n := len(resolved); n > 1 {
			subj += fmt.Sprintf(" (+%d more)", n-1)
		}
		if len(resolved) > 1 {
			heading = fmt.Sprintf("%d alerts resolved", len(resolved))
		} else {
			heading = "Alert resolved"
		}
	}

	md := mailData{Instance: g.InstanceName, Heading: heading, Severity: sev, Device: d.Name()}
	if d.Name() != d.Hostname {
		md.Rows = append(md.Rows, [2]string{"Host name", d.Hostname})
	}
	if d.OSName != "" {
		md.Rows = append(md.Rows, [2]string{"OS", d.OSName})
	}
	if areas, _ := s.store.ListAreas(ctx); len(areas) > 1 {
		for _, a := range areas {
			if a.ID == d.AreaID {
				md.Rows = append(md.Rows, [2]string{"Area", a.Name})
			}
		}
	}
	if !d.LastSeenAt.IsZero() {
		md.Rows = append(md.Rows, [2]string{"Last seen", d.LastSeenAt.Format("2006-01-02 15:04 MST")})
	}
	if base := s.cfg.BaseURL; base != "" {
		md.URL = base + "/devices/" + d.ID
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s – %s\n\n", heading, d.Name())
	for _, r := range md.Rows {
		fmt.Fprintf(&b, "%-10s %s\n", r[0]+":", r[1])
	}
	b.WriteString("\n")
	section := func(name string, list []store.Alert, resolvedList bool) {
		if len(list) == 0 {
			return
		}
		ms := mailSection{Title: name}
		fmt.Fprintf(&b, "%s\n%s\n", name, strings.Repeat("-", len(name)))
		for _, a := range list {
			ma := mailAlert{Title: title(a), Message: a.Message, Severity: a.Severity, Since: "since " + a.OpenedAt.Format("2006-01-02 15:04")}
			if resolvedList {
				ma.Severity = "resolved"
				ma.Since = "open since " + a.OpenedAt.Format("2006-01-02 15:04")
			}
			ms.Alerts = append(ms.Alerts, ma)
			fmt.Fprintf(&b, "* [%s] %s\n  %s\n  %s\n", strings.ToUpper(ma.Severity), ma.Title, ma.Message, ma.Since)
		}
		b.WriteString("\n")
		md.Sections = append(md.Sections, ms)
	}
	section("New alerts", opened, false)
	section("New events", updated, false)
	section("Increased", increased, false)
	section("Still open", renotify, false)
	section("Resolved", resolved, true)
	if md.URL != "" {
		fmt.Fprintf(&b, "Details: %s\n", md.URL)
	}
	return Mail{Subject: subj, Text: b.String(), HTML: renderMailHTML(md)}
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
func eventDetails(ctx context.Context, st *store.Store, deviceID, kind string, since time.Time, includeExternal bool) string {
	evs, err := st.Events(ctx, deviceID, since, 500)
	if err != nil {
		return ""
	}
	var msgs []string
	for _, e := range evs {
		if e.Kind == kind && (includeExternal || !e.External) {
			msgs = append(msgs, e.Message)
		}
	}
	return joinEventMessages(msgs)
}

// joinEventMessages lists up to three event messages.
func joinEventMessages(msgs []string) string {
	more := 0
	if len(msgs) > 3 {
		msgs, more = msgs[:3], len(msgs)-3
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
