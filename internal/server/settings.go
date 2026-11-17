package server

import (
	"context"

	"github.com/commifreak/inventory/internal/protocol"
)

// Setting keys.
const (
	setCollection = "collection"
	setUpdates    = "updates"
	setAlerts     = "alerts"
	setSMTP       = "smtp"
	setGeneral    = "general"
)

// Update rings.
const (
	RingTest   = "test"
	RingEarly  = "early"
	RingStable = "stable"
)

// Rings in rollout order.
var Rings = []string{RingTest, RingEarly, RingStable}

// UpdatePolicy controls agent self-updates.
type UpdatePolicy struct {
	// Paused stops all automatic updates. Manual "update now" still works.
	Paused bool `json:"paused"`
	// RingVersions maps a ring to its approved version. Empty = latest.
	RingVersions map[string]string `json:"ring_versions"`
}

func defaultUpdatePolicy() UpdatePolicy {
	return UpdatePolicy{RingVersions: map[string]string{}}
}

// SMTPSettings for alert mails.
type SMTPSettings struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Security    string `json:"security"` // starttls, tls, none
	Username    string `json:"username"`
	PasswordEnc string `json:"password_enc"`
	From        string `json:"from"`
}

// Configured reports whether mails can be sent.
func (s SMTPSettings) Configured() bool { return s.Host != "" && s.From != "" }

// AlertSettings controls alert evaluation and notification.
type AlertSettings struct {
	Recipients     []string              `json:"recipients"`
	RenotifyHours  int                   `json:"renotify_hours"` // 0 = never re-notify
	NotifyResolved bool                  `json:"notify_resolved"`
	Rules          map[string]RuleConfig `json:"rules"`
}

// RuleConfig is the configuration of one alert rule.
type RuleConfig struct {
	Enabled        bool               `json:"enabled"`
	Severity       string             `json:"severity"`
	Params         map[string]float64 `json:"params,omitempty"`
	SystemDiskOnly bool               `json:"system_disk_only,omitempty"`
	Recipients     []string           `json:"recipients,omitempty"` // overrides the global list
}

// GeneralSettings are miscellaneous options.
type GeneralSettings struct {
	InstanceName  string `json:"instance_name"`
	RetentionDays int    `json:"retention_days"`
}

func (s *Server) collectionConfig(ctx context.Context) protocol.AgentConfig {
	c := protocol.DefaultConfig()
	var stored protocol.AgentConfig
	if ok, _ := s.store.GetSetting(ctx, setCollection, &stored); ok {
		if stored.CheckinIntervalSec >= 60 {
			c.CheckinIntervalSec = stored.CheckinIntervalSec
		}
		for k, v := range stored.Intervals {
			c.Intervals[k] = v
		}
	}
	return c
}

func (s *Server) updatePolicy(ctx context.Context) UpdatePolicy {
	p := defaultUpdatePolicy()
	_, _ = s.store.GetSetting(ctx, setUpdates, &p)
	if p.RingVersions == nil {
		p.RingVersions = map[string]string{}
	}
	return p
}

func (s *Server) smtpSettings(ctx context.Context) SMTPSettings {
	c := SMTPSettings{Port: 587, Security: "starttls"}
	_, _ = s.store.GetSetting(ctx, setSMTP, &c)
	return c
}

func (s *Server) alertSettings(ctx context.Context) AlertSettings {
	a := AlertSettings{RenotifyHours: 24, NotifyResolved: true}
	_, _ = s.store.GetSetting(ctx, setAlerts, &a)
	if a.Rules == nil {
		a.Rules = map[string]RuleConfig{}
	}
	// Fill defaults for rules not configured yet.
	for _, def := range RuleCatalog {
		rc, ok := a.Rules[def.ID]
		if !ok {
			rc = RuleConfig{Enabled: def.DefaultEnabled, Severity: def.DefaultSeverity, SystemDiskOnly: def.DiskScope && def.DefaultSystemDiskOnly}
		}
		if rc.Severity == "" {
			rc.Severity = def.DefaultSeverity
		}
		if rc.Params == nil {
			rc.Params = map[string]float64{}
		}
		for _, p := range def.Params {
			if _, ok := rc.Params[p.Key]; !ok {
				rc.Params[p.Key] = p.Default
			}
		}
		a.Rules[def.ID] = rc
	}
	return a
}

func (s *Server) generalSettings(ctx context.Context) GeneralSettings {
	g := GeneralSettings{InstanceName: "Inventory", RetentionDays: 365}
	_, _ = s.store.GetSetting(ctx, setGeneral, &g)
	if g.RetentionDays < 7 {
		g.RetentionDays = 7
	}
	return g
}
