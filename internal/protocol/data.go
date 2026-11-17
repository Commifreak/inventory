package protocol

import "time"

// ---------------------------------------------------------------------------
// system collector
// ---------------------------------------------------------------------------

// SystemInfo is the payload of the "system" collector.
type SystemInfo struct {
	OS       OSInfo       `json:"os"`
	Hardware HardwareInfo `json:"hardware"`
	Volumes  []Volume     `json:"volumes"`
	Network  []NetAdapter `json:"network"`
	DNS      []string     `json:"dns,omitempty"`
	Gateways []string     `json:"gateways,omitempty"`
	WiFiSSID string       `json:"wifi_ssid,omitempty"`
	Users    UsersInfo    `json:"users"`
	Security SecurityInfo `json:"security"`
	Battery  []Battery    `json:"battery,omitempty"`
	// PiPower is set on Raspberry Pi boards.
	PiPower *PiPowerInfo `json:"pi_power,omitempty"`
}

type OSInfo struct {
	Family         string    `json:"family"`  // windows, linux, darwin
	Name           string    `json:"name"`    // "Windows 11 Pro", "Debian GNU/Linux 12 (bookworm)"
	Version        string    `json:"version"` // "10.0.26100.2314", "12"
	Build          string    `json:"build,omitempty"`
	DisplayVersion string    `json:"display_version,omitempty"` // "24H2"
	Edition        string    `json:"edition,omitempty"`
	DistroID       string    `json:"distro_id,omitempty"`      // os-release ID
	DistroVersion  string    `json:"distro_version,omitempty"` // os-release VERSION_ID
	Codename       string    `json:"codename,omitempty"`
	Kernel         string    `json:"kernel,omitempty"`
	Arch           string    `json:"arch"`
	InstallDate    time.Time `json:"install_date,omitzero"`
	BootTime       time.Time `json:"boot_time"`
	Timezone       string    `json:"timezone,omitempty"`
}

type HardwareInfo struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	BIOSVendor   string `json:"bios_vendor,omitempty"`
	BIOSVersion  string `json:"bios_version,omitempty"`
	BIOSDate     string `json:"bios_date,omitempty"`
	Board        string `json:"board,omitempty"`
	CPU          string `json:"cpu,omitempty"`
	CPUCores     int    `json:"cpu_cores,omitempty"`
	CPUThreads   int    `json:"cpu_threads,omitempty"`
	MemoryBytes  uint64 `json:"memory_bytes,omitempty"`
	Virtual      bool   `json:"virtual,omitempty"`
}

type Volume struct {
	Mount      string `json:"mount"` // "C:" or "/"
	Label      string `json:"label,omitempty"`
	FS         string `json:"fs,omitempty"`
	Device     string `json:"device,omitempty"`
	SizeBytes  uint64 `json:"size_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	System     bool   `json:"system,omitempty"` // holds the OS
	Encrypted  *bool  `json:"encrypted,omitempty"`
	Encryption string `json:"encryption,omitempty"` // "BitLocker (on)", "LUKS", "FileVault"
}

type NetAdapter struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	Gateways    []string `json:"gateways,omitempty"`
	DNS         []string `json:"dns,omitempty"`
	DHCP        *bool    `json:"dhcp,omitempty"`
	Up          bool     `json:"up"`
	Wireless    bool     `json:"wireless,omitempty"`
}

type UsersInfo struct {
	CurrentUsers []string    `json:"current_users,omitempty"`
	LastLogons   []UserLogon `json:"last_logons,omitempty"`
	Admins       []string    `json:"admins,omitempty"`
	AdminGroup   string      `json:"admin_group,omitempty"`
}

type UserLogon struct {
	User string    `json:"user"`
	Time time.Time `json:"time"`
	From string    `json:"from,omitempty"`
}

type SecurityInfo struct {
	SecureBoot *SecureBootInfo `json:"secure_boot,omitempty"`
	Defender   *DefenderInfo   `json:"defender,omitempty"`
	Activation *ActivationInfo `json:"activation,omitempty"`
	TPM        *TPMInfo        `json:"tpm,omitempty"`
}

type SecureBootInfo struct {
	Supported bool `json:"supported"` // UEFI with Secure Boot variables
	Enabled   bool `json:"enabled"`
	// Certificates found in the UEFI signature databases (db, KEK).
	DBHasWindowsUEFICA2023   *bool `json:"db_windows_uefi_ca_2023,omitempty"`
	DBHasMicrosoftUEFICA2023 *bool `json:"db_microsoft_uefi_ca_2023,omitempty"`
	DBHasOptionROMCA2023     *bool `json:"db_option_rom_ca_2023,omitempty"`
	// The 2011 third-party CA. Windows only adds the third-party 2023 CAs
	// (Microsoft UEFI CA 2023, Option ROM CA 2023) when this one is trusted.
	DBHasMicrosoftUEFICA2011 *bool `json:"db_microsoft_uefi_ca_2011,omitempty"`
	KEKHas2023               *bool `json:"kek_2023,omitempty"`
	// Windows servicing status (UEFICA2023Status), e.g. "Updated", "InProgress", "NotStarted".
	ServicingStatus string `json:"servicing_status,omitempty"`
	Error           string `json:"error,omitempty"`
}

type DefenderInfo struct {
	Present            bool      `json:"present"`
	ServiceEnabled     bool      `json:"service_enabled"`
	AntivirusEnabled   bool      `json:"antivirus_enabled"`
	RealTimeProtection bool      `json:"real_time_protection"`
	RunningMode        string    `json:"running_mode,omitempty"` // "Normal", "Passive", "EDR Block", "SxS Passive"
	SignatureUpdated   time.Time `json:"signature_updated,omitzero"`
	SignatureAgeDays   int       `json:"signature_age_days"`
	SignatureVersion   string    `json:"signature_version,omitempty"`
	LastQuickScan      time.Time `json:"last_quick_scan,omitzero"`
	TamperProtection   *bool     `json:"tamper_protection,omitempty"`
}

type ActivationInfo struct {
	Licensed bool   `json:"licensed"`
	Status   string `json:"status"` // Licensed, Unlicensed, OOBGrace, ...
	Product  string `json:"product,omitempty"`
	Channel  string `json:"channel,omitempty"`
}

type TPMInfo struct {
	Present bool   `json:"present"`
	Version string `json:"version,omitempty"`
}

// PiPowerInfo is the Raspberry Pi firmware throttling state
// ("vcgencmd get_throttled"). "Now" flags describe the current state,
// "SinceBoot" flags whether it happened since the last boot.
type PiPowerInfo struct {
	Source                 string `json:"source"` // "vcgencmd" or "hwmon"
	Raw                    string `json:"raw,omitempty"`
	UndervoltageNow        bool   `json:"undervoltage_now"`
	UndervoltageSinceBoot  bool   `json:"undervoltage_since_boot"`
	ThrottledNow           bool   `json:"throttled_now"`
	ThrottledSinceBoot     bool   `json:"throttled_since_boot"`
	FreqCappedNow          bool   `json:"freq_capped_now"`
	FreqCappedSinceBoot    bool   `json:"freq_capped_since_boot"`
	SoftTempLimitNow       bool   `json:"soft_temp_limit_now"`
	SoftTempLimitSinceBoot bool   `json:"soft_temp_limit_since_boot"`
}

type Battery struct {
	Name               string  `json:"name,omitempty"`
	DesignCapacity     float64 `json:"design_capacity"`      // mWh
	FullChargeCapacity float64 `json:"full_charge_capacity"` // mWh
	HealthPercent      float64 `json:"health_percent"`
	CycleCount         int     `json:"cycle_count,omitempty"`
	Status             string  `json:"status,omitempty"`
}

// ---------------------------------------------------------------------------
// smart collector
// ---------------------------------------------------------------------------

type SmartData struct {
	Source string `json:"source"` // "smartctl 7.5", "windows-storage"
	Disks  []Disk `json:"disks"`
}

type Disk struct {
	Device         string `json:"device"` // smartctl device name, e.g. /dev/sda
	Model          string `json:"model,omitempty"`
	Serial         string `json:"serial,omitempty"`
	Firmware       string `json:"firmware,omitempty"`
	Protocol       string `json:"protocol,omitempty"`   // ATA, NVMe, SCSI
	MediaType      string `json:"media_type,omitempty"` // SSD, HDD
	Bus            string `json:"bus,omitempty"`        // SATA, NVMe, USB
	SizeBytes      uint64 `json:"size_bytes,omitempty"`
	System         bool   `json:"system"`             // disk holding the OS
	External       bool   `json:"external,omitempty"` // USB / removable
	SmartSupported bool   `json:"smart_supported"`
	SmartEnabled   bool   `json:"smart_enabled"`
	// HealthPassed is the overall self-assessment. nil = unknown.
	HealthPassed *bool  `json:"health_passed,omitempty"`
	Temperature  *int   `json:"temperature,omitempty"` // °C
	PowerOnHours *int64 `json:"power_on_hours,omitempty"`
	PowerCycles  *int64 `json:"power_cycles,omitempty"`
	// ATA counters.
	Reallocated   *int64 `json:"reallocated,omitempty"`
	Pending       *int64 `json:"pending,omitempty"`
	Uncorrectable *int64 `json:"uncorrectable,omitempty"`
	CRCErrors     *int64 `json:"crc_errors,omitempty"`
	// NVMe health log.
	PercentUsed     *int     `json:"percent_used,omitempty"`
	AvailableSpare  *int     `json:"available_spare,omitempty"`
	SpareThreshold  *int     `json:"spare_threshold,omitempty"`
	MediaErrors     *int64   `json:"media_errors,omitempty"`
	CriticalWarning *int     `json:"critical_warning,omitempty"`
	UnsafeShutdowns *int64   `json:"unsafe_shutdowns,omitempty"`
	DataWrittenTB   *float64 `json:"data_written_tb,omitempty"`
	// Raw ATA attribute table for display.
	Attributes []SmartAttribute `json:"attributes,omitempty"`
	Messages   []string         `json:"messages,omitempty"` // smartctl messages / errors
}

type SmartAttribute struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Value     int    `json:"value"`
	Worst     int    `json:"worst"`
	Threshold int    `json:"thresh"`
	Raw       string `json:"raw"`
	Failing   string `json:"failing,omitempty"` // "now", "past"
}

// ---------------------------------------------------------------------------
// updates collector
// ---------------------------------------------------------------------------

type UpdatesData struct {
	Manager string `json:"manager"` // "Windows Update", "apt", "dnf", "zypper", "pacman", "softwareupdate"
	// Pending updates.
	Pending         []PendingUpdate      `json:"pending"`
	PendingCount    int                  `json:"pending_count"`
	SecurityCount   int                  `json:"security_count"`
	RebootRequired  bool                 `json:"reboot_required"`
	RebootReasons   []string             `json:"reboot_reasons,omitempty"`
	LastSearch      time.Time            `json:"last_search,omitzero"`
	LastInstall     time.Time            `json:"last_install,omitzero"`
	AutoUpdates     *bool                `json:"auto_updates,omitempty"`
	AutoUpdatesInfo string               `json:"auto_updates_info,omitempty"`
	Source          string               `json:"source,omitempty"` // "Windows Update", "WSUS: http://..."
	Services        []ServiceState       `json:"services,omitempty"`
	History         []UpdateHistoryEntry `json:"history,omitempty"`
	SearchError     string               `json:"search_error,omitempty"`
}

type PendingUpdate struct {
	Title    string    `json:"title"`
	KB       string    `json:"kb,omitempty"`
	Version  string    `json:"version,omitempty"`
	Category string    `json:"category,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Security bool      `json:"security,omitempty"`
	Released time.Time `json:"released,omitzero"`
	Size     uint64    `json:"size,omitempty"`
}

type UpdateHistoryEntry struct {
	Title     string    `json:"title"`
	Date      time.Time `json:"date"`
	Operation string    `json:"operation,omitempty"` // Installation, Uninstallation
	Result    string    `json:"result"`              // Succeeded, Failed, Aborted, SucceededWithErrors
	HResult   string    `json:"hresult,omitempty"`   // 0x80070002
	Message   string    `json:"message,omitempty"`
}

type ServiceState struct {
	Name      string `json:"name"`
	Display   string `json:"display,omitempty"`
	State     string `json:"state"`
	StartType string `json:"start_type,omitempty"`
}

// ---------------------------------------------------------------------------
// software collector
// ---------------------------------------------------------------------------

type SoftwareData struct {
	Items []SoftwareItem `json:"items"`
}

type SoftwareItem struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"` // as reported, YYYY-MM-DD if parseable
	Source      string `json:"source"`                 // registry, dpkg, rpm, pacman, snap, flatpak, app, brew
	Scope       string `json:"scope,omitempty"`        // machine, user:<name>
	Arch        string `json:"arch,omitempty"`
}

// Key identifies a software item for change tracking.
func (s SoftwareItem) Key() string { return s.Source + "|" + s.Scope + "|" + s.Name + "|" + s.Arch }

// ---------------------------------------------------------------------------
// autostart collector
// ---------------------------------------------------------------------------

type AutostartData struct {
	Items []AutostartItem `json:"items"`
}

type AutostartItem struct {
	Name     string `json:"name"`
	Command  string `json:"command,omitempty"`
	Location string `json:"location"`        // "HKLM\...\Run", "Startup folder", "Scheduled task", "Service", "systemd", "cron", "xdg", "LaunchDaemon"
	Scope    string `json:"scope,omitempty"` // machine, user:<name>
	Enabled  bool   `json:"enabled"`
	Vendor   bool   `json:"vendor,omitempty"` // shipped by the OS / distribution
}

// ---------------------------------------------------------------------------
// events collector
// ---------------------------------------------------------------------------

type EventsData struct {
	// Since is the start of the scanned window.
	Since  time.Time       `json:"since"`
	Events []CriticalEvent `json:"events"`
}

// Event kinds.
const (
	EventBluescreen = "bluescreen"
	EventDiskError  = "disk_error"
	EventOOM        = "oom"
	// EventUndervoltage: Raspberry Pi power supply voltage too low.
	EventUndervoltage = "undervoltage"
)

type CriticalEvent struct {
	Kind    string    `json:"kind"`
	Time    time.Time `json:"time"`
	Source  string    `json:"source,omitempty"` // provider / kernel subsystem
	EventID int       `json:"event_id,omitempty"`
	Device  string    `json:"device,omitempty"`
	Message string    `json:"message"`
	// Key deduplicates events across overlapping scans.
	Key string `json:"key"`
}
