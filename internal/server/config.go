package server

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from environment variables (see docs/CONFIGURATION.md).
type Config struct {
	ListenAddr           string
	DataDir              string
	AgentsDir            string
	BaseURL              string // public URL, e.g. https://inventory.example.com
	InitialAdminPassword string
	EncryptionKey        string
	TrustedProxies       []*net.IPNet
	LocalLogin           bool
	InsecureCookies      bool // testing only: never mark cookies Secure
	OIDC                 OIDCConfig
	SessionLifetime      time.Duration
	EOLFetch             bool
	// HAAddonRepo is the Home Assistant add-on repository shown on the install page.
	HAAddonRepo string
	Version     string
}

// OIDCConfig configures login via an OpenID Connect provider (Authentik, Authelia, ...).
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	AdminGroup   string // required group claim value; empty = every authenticated user
	GroupsClaim  string
	ButtonLabel  string
	Scopes       []string
}

// Enabled reports whether OIDC is configured.
func (o OIDCConfig) Enabled() bool { return o.Issuer != "" && o.ClientID != "" }

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envBool(key string, def bool) bool {
	v := env(key, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// LoadConfig reads the configuration from the environment.
func LoadConfig(version string) (Config, error) {
	c := Config{
		ListenAddr:           env("LISTEN_ADDR", ":8080"),
		DataDir:              env("DATA_DIR", "/data"),
		AgentsDir:            env("AGENTS_DIR", "/app/agents"),
		BaseURL:              strings.TrimRight(env("BASE_URL", ""), "/"),
		InitialAdminPassword: os.Getenv("INITIAL_ADMIN_PASSWORD"),
		EncryptionKey:        env("ENCRYPTION_KEY", ""),
		LocalLogin:           envBool("LOCAL_LOGIN", true),
		InsecureCookies:      envBool("INSECURE_COOKIES", false),
		SessionLifetime:      12 * time.Hour,
		EOLFetch:             envBool("EOL_FETCH", true),
		HAAddonRepo:          env("HA_ADDON_REPOSITORY", "https://github.com/Commifreak/inventory-ha-addon"),
		Version:              version,
		OIDC: OIDCConfig{
			Issuer:       strings.TrimSpace(env("OIDC_ISSUER", "")), // exact: Authentik's issuer ends with "/"
			ClientID:     env("OIDC_CLIENT_ID", ""),
			ClientSecret: env("OIDC_CLIENT_SECRET", ""),
			AdminGroup:   env("OIDC_ADMIN_GROUP", ""),
			GroupsClaim:  env("OIDC_GROUPS_CLAIM", "groups"),
			ButtonLabel:  env("OIDC_BUTTON_LABEL", "Sign in with SSO"),
			Scopes:       strings.Fields(env("OIDC_SCOPES", "openid profile email groups")),
		},
	}
	if v := env("SESSION_LIFETIME", ""); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("SESSION_LIFETIME: %w", err)
		}
		c.SessionLifetime = d
	}
	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return c, fmt.Errorf("BASE_URL must be an absolute http(s) URL, got %q", c.BaseURL)
		}
	}
	// Default: trust private networks (Docker networks, Traefik on the same host).
	proxies := env("TRUSTED_PROXIES", "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7")
	for _, p := range strings.Split(proxies, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if strings.Contains(p, ":") {
				p += "/128"
			} else {
				p += "/32"
			}
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return c, fmt.Errorf("TRUSTED_PROXIES: %w", err)
		}
		c.TrustedProxies = append(c.TrustedProxies, n)
	}
	if !c.LocalLogin && !c.OIDC.Enabled() {
		return c, fmt.Errorf("LOCAL_LOGIN=false requires OIDC to be configured")
	}
	return c, nil
}
