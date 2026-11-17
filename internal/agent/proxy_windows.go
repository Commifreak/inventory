package agent

import (
	"errors"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows proxy resolution (after the process environment):
//  1. machine-wide WinHTTP proxy ("netsh winhttp set proxy"),
//  2. WinINet settings ("Settings > Network > Proxy") of the user of the
//     active session - or machine-wide when the policy ProxySettingsPerUser=0
//     is set - incl. PAC script and automatic detection (WPAD), resolved by
//     the WinHTTP auto-proxy API. The last seen user settings are kept while
//     nobody is signed in.

var (
	modwinhttp                              = windows.NewLazySystemDLL("winhttp.dll")
	procWinHttpGetDefaultProxyConfiguration = modwinhttp.NewProc("WinHttpGetDefaultProxyConfiguration")
	procWinHttpOpen                         = modwinhttp.NewProc("WinHttpOpen")
	procWinHttpCloseHandle                  = modwinhttp.NewProc("WinHttpCloseHandle")
	procWinHttpSetTimeouts                  = modwinhttp.NewProc("WinHttpSetTimeouts")
	procWinHttpGetProxyForUrl               = modwinhttp.NewProc("WinHttpGetProxyForUrl")
	procGlobalFree                          = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
)

const (
	winhttpAccessTypeNoProxy    = 1
	winhttpAccessTypeNamedProxy = 3

	winhttpAutoProxyAutoDetect = 0x1
	winhttpAutoProxyConfigURL  = 0x2
	winhttpAutoDetectDHCP      = 0x1
	winhttpAutoDetectDNSA      = 0x2

	errWinhttpLoginFailure = 12015
)

type winhttpProxyInfo struct {
	accessType uint32
	proxy      *uint16
	bypass     *uint16
}

func (pi *winhttpProxyInfo) take() (proxy, bypass string) {
	if pi.proxy != nil {
		proxy = windows.UTF16PtrToString(pi.proxy)
		procGlobalFree.Call(uintptr(unsafe.Pointer(pi.proxy)))
	}
	if pi.bypass != nil {
		bypass = windows.UTF16PtrToString(pi.bypass)
		procGlobalFree.Call(uintptr(unsafe.Pointer(pi.bypass)))
	}
	return
}

type winhttpAutoProxyOptions struct {
	flags           uint32
	autoDetectFlags uint32
	autoConfigURL   *uint16
	reserved        uintptr
	reserved2       uint32
	autoLogon       int32
}

var (
	winMachineProxy settingsCache
	winUserProxy    settingsCache

	winLastUserMu sync.Mutex
	winLastUser   *proxySettings
)

func platformProxy(u *url.URL) (*url.URL, string) {
	if p, ok := winMachineProxy.get(winhttpDefaultProxy); ok {
		return p.proxyFor(u), p.Source
	}
	p, ok := winUserProxy.get(winUserProxySettings)
	if !ok {
		return nil, ""
	}
	if bypassProxy(u.Hostname(), p.Bypass, p.BypassSimple) {
		return nil, ""
	}
	if p.PAC != "" || p.AutoDetect {
		if proxy, resolved := autoProxy(u, p); resolved {
			src := p.Source + " (automatic detection)"
			if p.PAC != "" {
				src = p.Source + " (PAC " + p.PAC + ")"
			}
			return proxy, src
		}
	}
	if p.Server == "" {
		return nil, ""
	}
	return p.proxyFor(u), p.Source
}

// winhttpDefaultProxy reads the machine-wide WinHTTP proxy (netsh winhttp).
func winhttpDefaultProxy() (proxySettings, bool) {
	var pi winhttpProxyInfo
	r, _, _ := procWinHttpGetDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return proxySettings{}, false
	}
	proxy, bypass := pi.take()
	if pi.accessType != winhttpAccessTypeNamedProxy || proxy == "" {
		return proxySettings{}, false
	}
	p := proxySettings{Source: "WinHTTP (netsh winhttp)", Server: proxy}
	p.Bypass, p.BypassSimple = splitIEBypass(bypass)
	return p, true
}

const ieSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// winUserProxySettings reads the WinINet proxy settings that apply to the
// user of the active session.
func winUserProxySettings() (proxySettings, bool) {
	if perMachineProxyPolicy() {
		return readIESettings(registry.LOCAL_MACHINE, "machine-wide proxy settings (policy)")
	}
	sid, user := activeSessionUser()
	if sid != "" {
		k, err := registry.OpenKey(registry.USERS, sid, registry.ENUMERATE_SUB_KEYS)
		if err == nil {
			p, ok := readIESettings(k, "proxy settings of "+user)
			k.Close()
			winLastUserMu.Lock()
			if ok {
				winLastUser = &p
			} else {
				winLastUser = nil
			}
			winLastUserMu.Unlock()
			return p, ok
		}
	}
	// Nobody signed in: keep the settings of the last user.
	winLastUserMu.Lock()
	defer winLastUserMu.Unlock()
	if winLastUser != nil {
		return *winLastUser, true
	}
	return proxySettings{}, false
}

func perMachineProxyPolicy() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("ProxySettingsPerUser")
	return err == nil && v == 0
}

func readIESettings(root registry.Key, source string) (proxySettings, bool) {
	if k, err := registry.OpenKey(root, ieSettingsKey+`\Connections`, registry.QUERY_VALUE); err == nil {
		b, _, err := k.GetBinaryValue("DefaultConnectionSettings")
		k.Close()
		if err == nil {
			if p, ok := parseIEConnectionSettings(b); ok {
				p.Source = source
				return p, p.Server != "" || p.PAC != "" || p.AutoDetect
			}
		}
	}
	// Older format: plain values.
	k, err := registry.OpenKey(root, ieSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return proxySettings{}, false
	}
	defer k.Close()
	p := proxySettings{Source: source}
	if en, _, _ := k.GetIntegerValue("ProxyEnable"); en == 1 {
		p.Server, _, _ = k.GetStringValue("ProxyServer")
		bypass, _, _ := k.GetStringValue("ProxyOverride")
		p.Bypass, p.BypassSimple = splitIEBypass(bypass)
	}
	p.PAC, _, _ = k.GetStringValue("AutoConfigURL")
	return p, p.Server != "" || p.PAC != ""
}

// activeSessionUser returns SID and name of the user of the console session,
// or else of the first active (e.g. RDP) session.
func activeSessionUser() (sid, name string) {
	sessions := []uint32{windows.WTSGetActiveConsoleSessionId()}
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &info, &count) == nil {
		for _, s := range unsafe.Slice(info, count) {
			if s.State == windows.WTSActive {
				sessions = append(sessions, s.SessionID)
			}
		}
		windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	}
	for _, id := range sessions {
		if id == 0xFFFFFFFF {
			continue
		}
		var tok windows.Token
		if windows.WTSQueryUserToken(id, &tok) != nil {
			continue
		}
		tu, err := tok.GetTokenUser()
		tok.Close()
		if err != nil {
			continue
		}
		s := tu.User.Sid.String()
		return s, sidName(s)
	}
	return "", ""
}

type autoProxyResult struct {
	at      time.Time
	proxy   *url.URL
	success bool
}

var (
	autoProxyMu    sync.Mutex
	autoProxyCache = map[string]autoProxyResult{}
)

const autoProxyTTL = 10 * time.Minute

// autoProxy resolves the proxy for u via PAC/WPAD. Results (also failures)
// are cached; a resolution is abandoned after 30 seconds.
func autoProxy(u *url.URL, p proxySettings) (*url.URL, bool) {
	key := p.PAC + "|" + boolStr(p.AutoDetect) + "|" + u.Scheme + "://" + u.Host
	autoProxyMu.Lock()
	if r, ok := autoProxyCache[key]; ok && time.Since(r.at) < autoProxyTTL {
		autoProxyMu.Unlock()
		return r.proxy, r.success
	}
	autoProxyMu.Unlock()

	type res struct {
		proxy *url.URL
		ok    bool
		err   error
	}
	ch := make(chan res, 1)
	go func() {
		proxy, ok, err := winhttpGetProxyForURL(u.String(), p)
		ch <- res{proxy, ok, err}
	}()
	var r res
	select {
	case r = <-ch:
	case <-time.After(30 * time.Second):
		r.err = errors.New("timed out")
	}
	if r.err != nil {
		proxyLog.Debug("automatic proxy detection failed", "err", r.err)
	}
	autoProxyMu.Lock()
	autoProxyCache[key] = autoProxyResult{at: time.Now(), proxy: r.proxy, success: r.ok}
	autoProxyMu.Unlock()
	return r.proxy, r.ok
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// winhttpGetProxyForURL runs WinHttpGetProxyForUrl. ok is false when no
// PAC script could be found or evaluated.
func winhttpGetProxyForURL(target string, p proxySettings) (*url.URL, bool, error) {
	agent, _ := windows.UTF16PtrFromString("inventory-agent")
	h, _, err := procWinHttpOpen.Call(uintptr(unsafe.Pointer(agent)), winhttpAccessTypeNoProxy, 0, 0, 0)
	if h == 0 {
		return nil, false, err
	}
	defer procWinHttpCloseHandle.Call(h)
	procWinHttpSetTimeouts.Call(h, 10000, 10000, 10000, 10000)

	var opts winhttpAutoProxyOptions
	if p.PAC != "" {
		opts.flags |= winhttpAutoProxyConfigURL
		opts.autoConfigURL, _ = windows.UTF16PtrFromString(p.PAC)
	}
	if p.AutoDetect {
		opts.flags |= winhttpAutoProxyAutoDetect
		opts.autoDetectFlags = winhttpAutoDetectDHCP | winhttpAutoDetectDNSA
	}
	u, _ := windows.UTF16PtrFromString(target)
	var pi winhttpProxyInfo
	r, _, err := procWinHttpGetProxyForUrl.Call(h, uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == errWinhttpLoginFailure {
			opts.autoLogon = 1
			r, _, err = procWinHttpGetProxyForUrl.Call(h, uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&pi)))
		}
		if r == 0 {
			return nil, false, err
		}
	}
	proxy, _ := pi.take()
	if pi.accessType != winhttpAccessTypeNamedProxy {
		return nil, true, nil // PAC says DIRECT
	}
	scheme := "https"
	if strings.HasPrefix(target, "http://") {
		scheme = "http"
	}
	return proxyURL(selectProxy(proxy, scheme)), true, nil
}
