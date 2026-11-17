package agent

import (
	"encoding/binary"
	"net/url"
	"testing"
)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func proxyStr(u *url.URL) string {
	if u == nil {
		return "direct"
	}
	return u.String()
}

func TestSelectProxy(t *testing.T) {
	cases := []struct{ list, scheme, want string }{
		{"proxy:8080", "https", "proxy:8080"},
		{"http=p1:80;https=p2:443", "https", "p2:443"},
		{"http=p1:80;https=p2:443", "http", "p1:80"},
		{"http=p1:80", "https", ""},
		{"p1:80; p2:80", "https", "p1:80"},
		{"", "https", ""},
	}
	for _, c := range cases {
		if got := selectProxy(c.list, c.scheme); got != c.want {
			t.Errorf("selectProxy(%q, %q) = %q, want %q", c.list, c.scheme, got, c.want)
		}
	}
}

func TestBypassProxy(t *testing.T) {
	pat := []string{"*.corp.example", "10.*", ".internal", "example.org", "192.168.0.0/16", "169.254/16"}
	cases := map[string]bool{
		"a.corp.example": true, "corp.example": false, "10.1.2.3": true, "x.internal": true,
		"internal": true, "example.org": true, "www.example.org": true, "notexample.org": false,
		"192.168.178.5": true, "169.254.1.1": true, "inventory.example.com": false,
		"localhost": true, "127.0.0.1": true, "[::1]": true, "nas": false,
	}
	for host, want := range cases {
		if got := bypassProxy(host, pat, false); got != want {
			t.Errorf("bypassProxy(%q) = %v, want %v", host, got, want)
		}
	}
	if !bypassProxy("nas", nil, true) || !bypassProxy("nas", []string{"<local>"}, false) || bypassProxy("nas.lan", []string{"<local>"}, false) {
		t.Errorf("simple host names not handled")
	}
	if !bypassProxy("anything.example", []string{"*"}, false) {
		t.Errorf("* must bypass everything")
	}
}

func TestEnvFileProxy(t *testing.T) {
	env := parseEnvFile(`# proxy
PATH="/usr/local/sbin:/usr/bin"
export https_proxy="http://user:pw@proxy.lan:3128"
HTTP_PROXY=http://proxy.lan:3128
no_proxy='localhost,.lan,10.0.0.0/8'
`)
	p, ok := envFileProxy(env, "/etc/environment")
	if !ok {
		t.Fatal("no proxy found")
	}
	if got := proxyStr(p.proxyFor(mustURL("https://inv.example.com/api"))); got != "http://user:pw@proxy.lan:3128" {
		t.Errorf("https: %s", got)
	}
	if got := proxyStr(p.proxyFor(mustURL("https://nas.lan/"))); got != "direct" {
		t.Errorf("no_proxy ignored: %s", got)
	}
	if _, ok := envFileProxy(parseEnvFile("PATH=/bin\n"), "x"); ok {
		t.Errorf("proxy found in file without proxy variables")
	}
	// Only http_proxy: https URLs stay direct (like Go and curl).
	p, _ = envFileProxy(parseEnvFile("http_proxy=proxy:80\n"), "x")
	if got := proxyStr(p.proxyFor(mustURL("https://inv.example.com/"))); got != "direct" {
		t.Errorf("https used http_proxy: %s", got)
	}
}

func TestParseScutilProxy(t *testing.T) {
	out := `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  ExcludeSimpleHostnames : 1
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 8080
  HTTPProxy : proxy.example.com
  HTTPSEnable : 1
  HTTPSPort : 8443
  HTTPSProxy : secure.example.com
  ProxyAutoConfigEnable : 0
}`
	p := parseScutilProxy(out)
	if got := proxyStr(p.proxyFor(mustURL("https://inv.example.com/"))); got != "http://secure.example.com:8443" {
		t.Errorf("https: %s", got)
	}
	if got := proxyStr(p.proxyFor(mustURL("http://inv.example.com/"))); got != "http://proxy.example.com:8080" {
		t.Errorf("http: %s", got)
	}
	for _, h := range []string{"https://printer.local/", "https://169.254.3.4/", "https://nas/"} {
		if got := proxyStr(p.proxyFor(mustURL(h))); got != "direct" {
			t.Errorf("%s not bypassed: %s", h, got)
		}
	}
	if p := parseScutilProxy("<dictionary> {\n  HTTPEnable : 0\n}"); p.HTTPS != "" || p.HTTP != "" {
		t.Errorf("disabled proxy used: %+v", p)
	}
}

func TestParseIEConnectionSettings(t *testing.T) {
	blob := func(flags uint32, server, bypass, pac string) []byte {
		var b []byte
		u32 := func(v uint32) { b = binary.LittleEndian.AppendUint32(b, v) }
		str := func(s string) { u32(uint32(len(s))); b = append(b, s...) }
		u32(0x46)
		u32(7)
		u32(flags)
		str(server)
		str(bypass)
		str(pac)
		b = append(b, make([]byte, 32)...)
		return b
	}
	p, ok := parseIEConnectionSettings(blob(0x01|ieFlagProxy, "http=p:80;https=p:443", "*.lan;<local>", ""))
	if !ok || p.Server != "http=p:80;https=p:443" || !p.BypassSimple || len(p.Bypass) != 1 || p.AutoDetect {
		t.Fatalf("manual proxy: %+v", p)
	}
	if got := proxyStr(p.proxyFor(mustURL("https://inv.example.com/"))); got != "http://p:443" {
		t.Errorf("proxy: %s", got)
	}
	// Proxy server stored but disabled; auto detect and PAC on (Windows default is 0x09).
	p, ok = parseIEConnectionSettings(blob(0x01|ieFlagAutoConfig|ieFlagAutoDetect, "old:80", "", "http://wpad/proxy.pac"))
	if !ok || p.Server != "" || p.PAC != "http://wpad/proxy.pac" || !p.AutoDetect {
		t.Errorf("auto settings: %+v", p)
	}
	if _, ok := parseIEConnectionSettings([]byte{1, 2, 3}); ok {
		t.Errorf("short blob accepted")
	}
	if _, ok := parseIEConnectionSettings(blob(0x03, "x", "", "")[:20]); ok {
		t.Errorf("truncated blob accepted")
	}
}

func TestProxyURL(t *testing.T) {
	cases := map[string]string{"proxy:8080": "http://proxy:8080", "https://p:443": "https://p:443", "socks5://p:1080": "socks5://p:1080",
		"DIRECT": "direct", "": "direct", "ftp://p:21": "direct"}
	for in, want := range cases {
		if got := proxyStr(proxyURL(in)); got != want {
			t.Errorf("proxyURL(%q) = %s, want %s", in, got, want)
		}
	}
}
