package agent

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The agent uses the system proxy:
//
//  1. HTTPS_PROXY / HTTP_PROXY / NO_PROXY of the process environment,
//  2. the platform configuration (platformProxy):
//     Windows: machine-wide WinHTTP proxy (netsh winhttp), then the proxy
//     settings of the signed-in user incl. PAC script and automatic detection
//     (WPAD); Linux: /etc/environment; macOS: network settings (scutil).
//
// Proxy authentication is limited to Basic credentials in the proxy URL.

// proxySettings is a static proxy configuration read from a system source.
type proxySettings struct {
	Source string
	// Server is a WinINet proxy list: "host:port" for all schemes or the
	// per-scheme form "http=host:port;https=host:port".
	Server string
	// HTTPS and HTTP are separate proxies per URL scheme (environment, macOS).
	HTTPS, HTTP string
	Bypass      []string
	// BypassSimple bypasses host names without a dot (<local>,
	// ExcludeSimpleHostnames).
	BypassSimple bool
	PAC          string // PAC script URL (evaluated on Windows only)
	AutoDetect   bool   // WPAD (Windows only)
}

// proxyFor returns the static proxy for u, or nil for a direct connection.
func (p proxySettings) proxyFor(u *url.URL) *url.URL {
	if bypassProxy(u.Hostname(), p.Bypass, p.BypassSimple) {
		return nil
	}
	if p.Server != "" {
		return proxyURL(selectProxy(p.Server, u.Scheme))
	}
	if u.Scheme == "https" {
		return proxyURL(p.HTTPS)
	}
	return proxyURL(p.HTTP)
}

// proxyCacheTTL is how long system proxy settings are cached; changes are
// picked up without restarting the agent.
const proxyCacheTTL = 2 * time.Minute

// settingsCache caches proxy settings read from the system.
type settingsCache struct {
	mu  sync.Mutex
	at  time.Time
	val proxySettings
	ok  bool
}

func (c *settingsCache) get(load func() (proxySettings, bool)) (proxySettings, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.at.IsZero() || time.Since(c.at) > proxyCacheTTL {
		c.val, c.ok = load()
		c.at = time.Now()
	}
	return c.val, c.ok
}

// proxyLog receives proxy changes; Run sets the agent logger.
var proxyLog = slog.Default()

var (
	proxyMu   sync.Mutex
	proxyLast = "-"
)

func noteProxy(p *url.URL, source string) {
	desc := "direct"
	if p != nil {
		desc = p.Redacted() + " (" + source + ")"
	}
	proxyMu.Lock()
	changed := desc != proxyLast
	proxyLast = desc
	proxyMu.Unlock()
	if changed {
		proxyLog.Info("proxy", "using", desc)
	}
}

func envProxyConfigured() bool {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// systemProxy is the Proxy function of the agent's HTTP transport.
func systemProxy(r *http.Request) (*url.URL, error) {
	p, source, err := ProxyFor(r.URL)
	if err != nil {
		return nil, err
	}
	noteProxy(p, source)
	return p, nil
}

// ProxyFor returns the proxy used for u and where it was configured
// (nil = direct connection).
func ProxyFor(u *url.URL) (*url.URL, string, error) {
	if envProxyConfigured() {
		p, err := http.ProxyFromEnvironment(&http.Request{URL: u})
		return p, "environment", err
	}
	p, source := platformProxy(u)
	return p, source, nil
}

// selectProxy picks the entry of a proxy list for a URL scheme. Entries are
// separated by ';' or whitespace; "scheme=host:port" entries win over plain
// ones. Without a matching entry the connection is direct.
func selectProxy(list, scheme string) string {
	generic := ""
	for _, e := range strings.FieldsFunc(list, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' }) {
		if k, v, ok := strings.Cut(e, "="); ok {
			if strings.EqualFold(k, scheme) {
				return v
			}
			continue
		}
		if generic == "" {
			generic = e
		}
	}
	return generic
}

// proxyURL turns "host:port" or a URL into a proxy URL; nil if unusable.
func proxyURL(s string) *url.URL {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "DIRECT") {
		return nil
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
		return u
	}
	return nil
}

// bypassProxy reports whether host must be reached directly. Patterns:
// "<local>", globs ("*.example.com", "10.*"), domains (".example.com" or
// "example.com", both also matching subdomains), CIDRs ("10.0.0.0/8", macOS
// "169.254/16") and "*".
func bypassProxy(host string, patterns []string, simple bool) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return true
	}
	if simple && ip == nil && !strings.Contains(host, ".") {
		return true
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case p == "":
		case p == "<local>":
			if ip == nil && !strings.Contains(host, ".") {
				return true
			}
		case strings.Contains(p, "/"):
			if _, n, err := net.ParseCIDR(padCIDR(p)); err == nil && ip != nil && n.Contains(ip) {
				return true
			}
		case strings.Contains(p, "*"):
			if globMatch(p, host) {
				return true
			}
		default:
			if h, _, err := net.SplitHostPort(p); err == nil {
				p = h
			}
			d := strings.TrimPrefix(p, ".")
			if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		}
	}
	return false
}

// padCIDR completes abbreviated IPv4 CIDRs ("169.254/16" -> "169.254.0.0/16").
func padCIDR(p string) string {
	addr, bits, _ := strings.Cut(p, "/")
	if strings.Contains(addr, ":") {
		return p
	}
	for strings.Count(addr, ".") < 3 {
		addr += ".0"
	}
	return addr + "/" + bits
}

func globMatch(pattern, s string) bool {
	re := "^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	ok, _ := regexp.MatchString(re, s)
	return ok
}

// parseEnvFile parses KEY=VALUE files such as /etc/environment.
func parseEnvFile(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// envFileProxy builds proxy settings from parsed environment variables.
func envFileProxy(env map[string]string, source string) (proxySettings, bool) {
	get := func(k string) string {
		if v := env[strings.ToLower(k)]; v != "" {
			return v
		}
		return env[strings.ToUpper(k)]
	}
	https, http := get("https_proxy"), get("http_proxy")
	if https == "" && http == "" {
		return proxySettings{}, false
	}
	// Like Go and curl: https:// URLs use only https_proxy.
	p := proxySettings{Source: source, HTTPS: https, HTTP: http}
	if np := get("no_proxy"); np != "" {
		p.Bypass = strings.Split(np, ",")
	}
	return p, true
}

// parseScutilProxy parses the output of "scutil --proxy" (macOS).
func parseScutilProxy(out string) proxySettings {
	p := proxySettings{Source: "macOS network settings"}
	kv := map[string]string{}
	inExceptions := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if inExceptions {
			if line == "}" {
				inExceptions = false
				continue
			}
			if _, v, ok := strings.Cut(line, " : "); ok {
				p.Bypass = append(p.Bypass, strings.TrimSpace(v))
			}
			continue
		}
		k, v, ok := strings.Cut(line, " : ")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "ExceptionsList" && strings.HasPrefix(v, "<array>") {
			inExceptions = true
			continue
		}
		kv[k] = v
	}
	hostPort := func(prefix string) string {
		if kv[prefix+"Enable"] != "1" || kv[prefix+"Proxy"] == "" {
			return ""
		}
		if port := kv[prefix+"Port"]; port != "" {
			return net.JoinHostPort(kv[prefix+"Proxy"], port)
		}
		return kv[prefix+"Proxy"]
	}
	p.HTTPS = hostPort("HTTPS")
	p.HTTP = hostPort("HTTP")
	p.BypassSimple = kv["ExcludeSimpleHostnames"] == "1"
	if kv["ProxyAutoConfigEnable"] == "1" {
		p.PAC = kv["ProxyAutoConfigURLString"]
	}
	p.AutoDetect = kv["ProxyAutoDiscoveryEnable"] == "1"
	return p
}

// WinINet connection flags (DefaultConnectionSettings).
const (
	ieFlagProxy      = 0x02
	ieFlagAutoConfig = 0x04
	ieFlagAutoDetect = 0x08
)

// parseIEConnectionSettings decodes the WinINet "DefaultConnectionSettings"
// registry blob: version, counter, flags, then length-prefixed proxy server,
// bypass list and PAC URL.
func parseIEConnectionSettings(b []byte) (proxySettings, bool) {
	if len(b) < 16 {
		return proxySettings{}, false
	}
	flags := binary.LittleEndian.Uint32(b[8:])
	pos := 12
	next := func() (string, bool) {
		if pos+4 > len(b) {
			return "", false
		}
		n := int(binary.LittleEndian.Uint32(b[pos:]))
		pos += 4
		if n < 0 || pos+n > len(b) {
			return "", false
		}
		s := string(b[pos : pos+n])
		pos += n
		return s, true
	}
	server, ok1 := next()
	bypass, ok2 := next()
	pac, ok3 := next()
	if !ok1 || !ok2 || !ok3 {
		return proxySettings{}, false
	}
	var p proxySettings
	if flags&ieFlagProxy != 0 {
		p.Server = server
		p.Bypass, p.BypassSimple = splitIEBypass(bypass)
	}
	if flags&ieFlagAutoConfig != 0 {
		p.PAC = pac
	}
	p.AutoDetect = flags&ieFlagAutoDetect != 0
	return p, true
}

// splitIEBypass splits a WinINet bypass list ("*.local;10.*;<local>").
func splitIEBypass(s string) ([]string, bool) {
	var out []string
	simple := false
	for _, e := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ' ' || r == ',' }) {
		if strings.EqualFold(e, "<local>") {
			simple = true
			continue
		}
		out = append(out, e)
	}
	return out, simple
}
