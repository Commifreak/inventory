// Package protocol defines the wire format between agent and server.
//
// All endpoints live below /api/agent/v1. Requests and responses are JSON.
// Report bodies may be gzip-compressed (Content-Encoding: gzip).
package protocol

import "time"

// APIPrefix is the path prefix of all agent endpoints. Reverse proxies must
// not put interactive authentication (forward auth) in front of it.
const APIPrefix = "/api/agent/v1"

// Version of the agent protocol. Bumped on incompatible changes only.
const Version = 1

// Platform identifiers.
const (
	OSWindows = "windows"
	OSLinux   = "linux"
	OSDarwin  = "darwin"
)

// InstallTag is the configuration embedded into an installer by the server.
// It is everything an agent needs to enroll without user interaction.
type InstallTag struct {
	ServerURL       string `json:"server_url"`
	EnrollmentToken string `json:"enrollment_token"`
}

// Identity describes the machine an agent runs on. It is used to recognise
// a machine again after a reinstall.
type Identity struct {
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	HardwareID string `json:"hardware_id"` // SMBIOS UUID (Windows/Linux) or IOPlatformUUID (macOS)
	MachineID  string `json:"machine_id"`  // MachineGuid / /etc/machine-id
}

// EnrollRequest is sent once with the enrollment token from the installer.
type EnrollRequest struct {
	Token        string   `json:"token"`
	Identity     Identity `json:"identity"`
	AgentVersion string   `json:"agent_version"`
}

// EnrollResponse carries the per-device credential. The agent stores it
// locally and uses it as bearer token: "Authorization: Bearer <credential>".
type EnrollResponse struct {
	DeviceID   string      `json:"device_id"`
	Credential string      `json:"credential"`
	Config     AgentConfig `json:"config"`
}

// CheckinRequest is the periodic heartbeat.
type CheckinRequest struct {
	AgentVersion string    `json:"agent_version"`
	Identity     Identity  `json:"identity"`
	BootTime     time.Time `json:"boot_time"`
	AgentTime    time.Time `json:"agent_time"`
	// LastCollected maps collector name to the time of its last successful run.
	LastCollected map[string]time.Time `json:"last_collected,omitzero"`
	// UpdateResult is set once after an update attempt.
	UpdateResult *UpdateResult `json:"update_result,omitempty"`
}

// CheckinResponse returns the current configuration and optional work.
type CheckinResponse struct {
	Config AgentConfig `json:"config"`
	// Update is set when the agent should install another version.
	Update *UpdateOffer `json:"update,omitempty"`
	// CollectNow lists collectors the agent should run immediately.
	CollectNow []string `json:"collect_now,omitempty"`
	// Revoked tells the agent that the device was removed on the server.
	// The agent stops reporting but does not uninstall itself.
	Revoked    bool      `json:"revoked,omitempty"`
	ServerTime time.Time `json:"server_time"`
}

// AgentConfig is pushed by the server on every check-in.
type AgentConfig struct {
	CheckinIntervalSec int `json:"checkin_interval_sec"`
	// Intervals maps collector name to its run interval in seconds.
	// A collector missing from the map or with interval <= 0 is disabled.
	Intervals map[string]int `json:"intervals"`
}

// UpdateOffer points to a signed agent binary.
type UpdateOffer struct {
	Version   string `json:"version"`
	URL       string `json:"url"` // absolute or relative to the server URL
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"` // base64 ed25519 signature, see package release
	Size      int64  `json:"size"`
}

// UpdateResult reports the outcome of an update attempt.
type UpdateResult struct {
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	Time        time.Time `json:"time"`
}

// Report carries the output of one or more collectors.
type Report struct {
	AgentVersion string             `json:"agent_version"`
	Sections     map[string]Section `json:"sections"`
}

// Section is the output of a single collector run.
type Section struct {
	CollectedAt time.Time `json:"collected_at"`
	DurationMs  int64     `json:"duration_ms"`
	// Error is set when the collector failed completely.
	Error string `json:"error,omitempty"`
	// Warnings lists partial failures (e.g. one disk could not be read).
	Warnings []string `json:"warnings,omitempty"`
	// Data is the collector specific payload (see types in this package).
	Data any `json:"data,omitempty"`
}

// Collector names.
const (
	CollectSystem    = "system"   // OS, hardware, volumes, network, users, security
	CollectSMART     = "smart"    // disks and SMART data
	CollectUpdates   = "updates"  // Windows Update / package manager state
	CollectSoftware  = "software" // installed software
	CollectAutostart = "autostart"
	CollectEvents    = "events" // critical events (bluescreens, disk errors, OOM)
)

// AllCollectors in a stable order.
var AllCollectors = []string{CollectSystem, CollectSMART, CollectUpdates, CollectSoftware, CollectAutostart, CollectEvents}

// DefaultConfig returns the defaults agreed in the specification.
func DefaultConfig() AgentConfig {
	return AgentConfig{
		CheckinIntervalSec: 15 * 60,
		Intervals: map[string]int{
			CollectSystem:    12 * 3600,
			CollectSMART:     4 * 3600,
			CollectUpdates:   4 * 3600,
			CollectSoftware:  12 * 3600,
			CollectAutostart: 12 * 3600,
			CollectEvents:    4 * 3600,
		},
	}
}
