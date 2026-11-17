// Package agent implements the Inventory agent: enrollment, scheduling of
// collectors, reporting and self-updates.
package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Config is the persistent agent configuration (config.json in the data dir).
type Config struct {
	ServerURL       string `json:"server_url"`
	EnrollmentToken string `json:"enrollment_token,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	// Credential is protected (DPAPI on Windows) before it is written.
	Credential string `json:"credential,omitempty"`
}

// State is volatile agent state (state.json in the data dir).
type State struct {
	LastRun       map[string]time.Time   `json:"last_run"`
	ServerConfig  *protocol.AgentConfig  `json:"server_config,omitempty"`
	PendingUpdate *PendingUpdate         `json:"pending_update,omitempty"`
	UpdateResult  *protocol.UpdateResult `json:"update_result,omitempty"`
	Revoked       bool                   `json:"revoked,omitempty"`
	EventsSince   time.Time              `json:"events_since,omitempty"`
	LastCheckin   time.Time              `json:"last_checkin,omitempty"`
	LastError     string                 `json:"last_error,omitempty"`
}

// PendingUpdate tracks an update across the restart.
type PendingUpdate struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	StartedAt time.Time `json:"started_at"`
	Attempts  int       `json:"attempts"`
}

func configPath() string { return filepath.Join(DataDir(), "config.json") }
func statePath() string  { return filepath.Join(DataDir(), "state.json") }

// LoadConfig reads the configuration.
func LoadConfig() (*Config, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Credential != "" {
		plain, err := unprotect(c.Credential)
		if err != nil {
			return nil, err
		}
		c.Credential = plain
	}
	return &c, nil
}

// SaveConfig writes the configuration atomically.
func SaveConfig(c *Config) error {
	out := *c
	if out.Credential != "" {
		enc, err := protect(out.Credential)
		if err != nil {
			return err
		}
		out.Credential = enc
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(configPath(), b, 0o600)
}

// LoadState reads the state; a missing or corrupt file yields an empty state.
func LoadState() *State {
	s := &State{LastRun: map[string]time.Time{}}
	b, err := os.ReadFile(statePath())
	if err == nil {
		_ = json.Unmarshal(b, s)
	}
	if s.LastRun == nil {
		s.LastRun = map[string]time.Time{}
	}
	return s
}

// SaveState writes the state atomically.
func SaveState(s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(), b, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ErrNotInstalled is returned when the agent has no configuration.
var ErrNotInstalled = errors.New("agent is not installed")
