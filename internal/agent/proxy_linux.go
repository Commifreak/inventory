package agent

import (
	"net/url"
	"os"
)

var linuxProxy settingsCache

// platformProxy reads http(s)_proxy/no_proxy from /etc/environment, which
// systemd does not pass to services. Variables of the service environment
// (e.g. systemd DefaultEnvironment) are handled before as process environment.
func platformProxy(u *url.URL) (*url.URL, string) {
	p, ok := linuxProxy.get(func() (proxySettings, bool) {
		b, err := os.ReadFile("/etc/environment")
		if err != nil {
			return proxySettings{}, false
		}
		return envFileProxy(parseEnvFile(string(b)), "/etc/environment")
	})
	if !ok {
		return nil, ""
	}
	return p.proxyFor(u), p.Source
}
