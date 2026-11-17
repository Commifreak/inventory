package agent

import (
	"context"
	"net/url"
	"os/exec"
	"sync"
	"time"
)

var (
	darwinProxy   settingsCache
	darwinPACOnce sync.Once
)

// platformProxy uses the proxy of the macOS network settings ("scutil
// --proxy"). PAC scripts and auto discovery are not evaluated.
func platformProxy(u *url.URL) (*url.URL, string) {
	p, ok := darwinProxy.get(func() (proxySettings, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--proxy").Output()
		if err != nil {
			return proxySettings{}, false
		}
		return parseScutilProxy(string(out)), true
	})
	if !ok {
		return nil, ""
	}
	if (p.PAC != "" || p.AutoDetect) && p.HTTPS == "" && p.HTTP == "" {
		darwinPACOnce.Do(func() {
			proxyLog.Warn("the macOS proxy is configured via PAC script or auto discovery, which the agent does not evaluate - set a static HTTPS proxy or HTTPS_PROXY")
		})
	}
	return p.proxyFor(u), p.Source
}
