package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/commifreak/inventory/internal/protocol"
)

// smartctl JSON output (smartmontools >= 7.0), only the fields we use.
type smartctlScan struct {
	Devices []struct {
		Name     string `json:"name"`
		InfoName string `json:"info_name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"devices"`
	Smartctl smartctlMeta `json:"smartctl"`
}

type smartctlMeta struct {
	Version    []int `json:"version"`
	ExitStatus int   `json:"exit_status"`
	Messages   []struct {
		String   string `json:"string"`
		Severity string `json:"severity"`
	} `json:"messages"`
}

type smartctlInfo struct {
	Smartctl smartctlMeta `json:"smartctl"`
	Device   struct {
		Name     string `json:"name"`
		InfoName string `json:"info_name"`
		Type     string `json:"type"`
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelName       string `json:"model_name"`
	ModelFamily     string `json:"model_family"`
	ScsiVendor      string `json:"scsi_vendor"`
	ScsiProduct     string `json:"scsi_product"`
	SerialNumber    string `json:"serial_number"`
	FirmwareVersion string `json:"firmware_version"`
	UserCapacity    struct {
		Bytes uint64 `json:"bytes"`
	} `json:"user_capacity"`
	NVMeTotalCapacity uint64 `json:"nvme_total_capacity"`
	RotationRate      *int   `json:"rotation_rate"`
	SmartSupport      struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours int64 `json:"hours"`
	} `json:"power_on_time"`
	PowerCycleCount *int64 `json:"power_cycle_count"`
	ATAAttributes   *struct {
		Table []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			Value      int    `json:"value"`
			Worst      int    `json:"worst"`
			Thresh     int    `json:"thresh"`
			WhenFailed string `json:"when_failed"`
			Raw        struct {
				Value  int64  `json:"value"`
				String string `json:"string"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMeLog *struct {
		CriticalWarning  int   `json:"critical_warning"`
		Temperature      int   `json:"temperature"`
		AvailableSpare   int   `json:"available_spare"`
		SpareThreshold   int   `json:"available_spare_threshold"`
		PercentageUsed   int   `json:"percentage_used"`
		DataUnitsWritten int64 `json:"data_units_written"`
		PowerCycles      int64 `json:"power_cycles"`
		PowerOnHours     int64 `json:"power_on_hours"`
		UnsafeShutdowns  int64 `json:"unsafe_shutdowns"`
		MediaErrors      int64 `json:"media_errors"`
	} `json:"nvme_smart_health_information_log"`
	SCSIGrownDefects *int64 `json:"scsi_grown_defect_list"`
}

// smartctlVersion formats the version array.
func (m smartctlMeta) version() string {
	var parts []string
	for _, v := range m.Version {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ".")
}

// runSmartctl executes smartctl with JSON output. smartctl uses its exit
// code as a bit mask; output is valid unless bits 0 or 1 are set.
func runSmartctl(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, append([]string{"-j"}, args...)...)
	hideWindow(cmd)
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode()&0x3 != 0 && len(out) == 0 {
			return nil, fmt.Errorf("smartctl %s: exit status %d", strings.Join(args, " "), ee.ExitCode())
		}
		return out, nil
	}
	return out, err
}

// SmartctlDisks scans and reads all disks smartctl can see.
func SmartctlDisks(ctx context.Context, bin string) (disks []protocol.Disk, version string, warnings []string, err error) {
	out, err := runSmartctl(ctx, bin, "--scan-open")
	if err != nil {
		return nil, "", nil, err
	}
	var scan smartctlScan
	if err := json.Unmarshal(out, &scan); err != nil {
		return nil, "", nil, fmt.Errorf("parse smartctl scan: %w", err)
	}
	version = "smartctl " + scan.Smartctl.version()
	seen := map[string]bool{}
	for _, d := range scan.Devices {
		args := []string{"-a"}
		if d.Type != "" {
			args = append(args, "-d", d.Type)
		}
		args = append(args, d.Name)
		out, err := runSmartctl(ctx, bin, args...)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", d.Name, err))
			continue
		}
		disk, err := ParseSmartctl(out)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", d.Name, err))
			continue
		}
		if disk.Device == "" {
			disk.Device = d.Name
		}
		// The same disk can show up twice (e.g. via different drivers).
		key := disk.Serial
		if key == "" {
			key = disk.Device
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if strings.Contains(strings.ToLower(d.InfoName), "usb") || strings.HasPrefix(d.Type, "usb") || strings.HasPrefix(d.Type, "snt") {
			disk.External = true
			disk.Bus = "USB"
		}
		disks = append(disks, disk)
	}
	return disks, version, warnings, nil
}

// ParseSmartctl converts "smartctl -a -j" output.
func ParseSmartctl(out []byte) (protocol.Disk, error) {
	var in smartctlInfo
	if err := json.Unmarshal(out, &in); err != nil {
		return protocol.Disk{}, err
	}
	d := protocol.Disk{
		Device:         in.Device.Name,
		Model:          strings.TrimSpace(in.ModelName),
		Serial:         strings.TrimSpace(in.SerialNumber),
		Firmware:       strings.TrimSpace(in.FirmwareVersion),
		Protocol:       in.Device.Protocol,
		SizeBytes:      in.UserCapacity.Bytes,
		SmartSupported: in.SmartSupport.Available,
		SmartEnabled:   in.SmartSupport.Enabled,
	}
	if d.Model == "" {
		d.Model = strings.TrimSpace(in.ScsiVendor + " " + in.ScsiProduct)
	}
	if d.SizeBytes == 0 {
		d.SizeBytes = in.NVMeTotalCapacity
	}
	if in.SmartStatus != nil {
		p := in.SmartStatus.Passed
		d.HealthPassed = &p
	}
	if in.Temperature != nil && in.Temperature.Current > 0 {
		t := in.Temperature.Current
		d.Temperature = &t
	}
	if in.PowerOnTime != nil {
		h := in.PowerOnTime.Hours
		d.PowerOnHours = &h
	}
	d.PowerCycles = in.PowerCycleCount
	switch {
	case in.Device.Protocol == "NVMe" || in.NVMeLog != nil:
		d.Protocol = "NVMe"
		d.MediaType = "SSD"
		d.Bus = "NVMe"
		// NVMe always supports the health log.
		d.SmartSupported, d.SmartEnabled = true, true
	case in.RotationRate != nil && *in.RotationRate == 0:
		d.MediaType = "SSD"
	case in.RotationRate != nil && *in.RotationRate > 0:
		d.MediaType = "HDD"
	}
	if d.Protocol == "ATA" && d.Bus == "" {
		d.Bus = "SATA"
	}
	if l := in.NVMeLog; l != nil {
		cw, sp, th, pu := l.CriticalWarning, l.AvailableSpare, l.SpareThreshold, l.PercentageUsed
		d.CriticalWarning, d.AvailableSpare, d.SpareThreshold, d.PercentUsed = &cw, &sp, &th, &pu
		me, us := l.MediaErrors, l.UnsafeShutdowns
		d.MediaErrors, d.UnsafeShutdowns = &me, &us
		if d.PowerOnHours == nil {
			h := l.PowerOnHours
			d.PowerOnHours = &h
		}
		if d.PowerCycles == nil {
			pc := l.PowerCycles
			d.PowerCycles = &pc
		}
		if d.Temperature == nil && l.Temperature > 0 {
			t := l.Temperature
			d.Temperature = &t
		}
		// One data unit is 1000 * 512 bytes.
		tb := float64(l.DataUnitsWritten) * 512000 / 1e12
		d.DataWrittenTB = &tb
	}
	if a := in.ATAAttributes; a != nil {
		for _, at := range a.Table {
			raw := at.Raw.Value
			attr := protocol.SmartAttribute{ID: at.ID, Name: at.Name, Value: at.Value, Worst: at.Worst, Threshold: at.Thresh, Raw: at.Raw.String}
			switch at.WhenFailed {
			case "now", "past":
				attr.Failing = at.WhenFailed
			}
			d.Attributes = append(d.Attributes, attr)
			v := raw
			switch at.ID {
			case 5:
				d.Reallocated = &v
			case 197:
				d.Pending = &v
			case 198:
				d.Uncorrectable = &v
			case 199:
				d.CRCErrors = &v
			case 194, 190:
				// Temperature raw values pack min/max into the upper bytes.
				if d.Temperature == nil {
					t := int(raw & 0xff)
					if t > 0 && t < 120 {
						d.Temperature = &t
					}
				}
			}
		}
	}
	if in.SCSIGrownDefects != nil && d.Reallocated == nil {
		d.Reallocated = in.SCSIGrownDefects
	}
	for _, m := range in.Smartctl.Messages {
		if m.Severity == "error" || m.Severity == "warning" {
			d.Messages = append(d.Messages, m.String)
		}
	}
	return d, nil
}
