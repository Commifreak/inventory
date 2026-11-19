package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// testEOLCycles is a small excerpt of endoflife.date data for tests.
func testEOLCycles() map[string][]eolCycle {
	c := func(cycle, eol string) eolCycle { return eolCycle{Cycle: cycle, EOL: json.RawMessage(`"` + eol + `"`)} }
	return map[string][]eolCycle{
		"windows": {c("11-24h2-w", "2026-10-13"), c("11-24h2-e", "2027-10-12"), c("10-22h2", "2025-10-14")},
		"office":  {c("2024", "2029-10-09"), c("2024-ltsc", "2029-10-09"), c("2021", "2026-10-13"), c("2019", "2025-10-14"), c("2016", "2025-10-14")},
	}
}

func TestEOLFetchWarning(t *testing.T) {
	up := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `[{"cycle":"2021","eol":"2026-10-13"}]`)
	}))
	defer ts.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	now := time.Now()

	// Fresh installation without cache: warn after the second failed attempt.
	e := newEOLData(t.TempDir(), true, log)
	e.api = ts.URL + "/"
	if e.refresh(ctx) || e.Warning(now) != "" {
		t.Fatalf("first failure must not warn yet")
	}
	if e.refresh(ctx) {
		t.Fatalf("refresh reported success")
	}
	if w := e.Warning(now); !strings.Contains(w, "HTTP 503") || !strings.Contains(w, "not checked") {
		t.Fatalf("unexpected warning: %q", w)
	}
	// Success clears the warning.
	up = true
	if !e.refresh(ctx) || e.Warning(now) != "" {
		t.Fatalf("warning not cleared after success")
	}

	// Cached data: warn only once the last success is older than three days.
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "eol"), 0o755)
	f := filepath.Join(dir, "eol", "office.json")
	_ = os.WriteFile(f, []byte(`[{"cycle":"2021","eol":"2026-10-13"}]`), 0o644)
	old := now.Add(-2 * 24 * time.Hour)
	_ = os.Chtimes(f, old, old)
	e = newEOLData(dir, true, log)
	e.api = ts.URL + "/"
	up = false
	e.refresh(ctx)
	if w := e.Warning(now); w != "" {
		t.Fatalf("warned although the cache is recent: %q", w)
	}
	if w := e.Warning(now.Add(2 * 24 * time.Hour)); !strings.Contains(w, "may be outdated") {
		t.Fatalf("expected stale warning, got %q", w)
	}
	// Disabled fetching never warns.
	e.fetch = false
	if e.Warning(now.Add(30*24*time.Hour)) != "" {
		t.Fatalf("warning with EOL_FETCH=false")
	}
}

func TestEOLKeyWindowsLTSC(t *testing.T) {
	cases := []struct {
		os   protocol.OSInfo
		want string
	}{
		{protocol.OSInfo{Family: "windows", Name: "Windows 11 IoT Enterprise LTSC 2024", DisplayVersion: "24H2", Edition: "IoTEnterpriseS", Build: "26100.9974"}, "11-24h2-iot-lts,11-24h2-e-lts"},
		{protocol.OSInfo{Family: "windows", Name: "Windows 11 Enterprise LTSC 2024", DisplayVersion: "24H2", Edition: "EnterpriseS"}, "11-24h2-e-lts"},
		{protocol.OSInfo{Family: "windows", Name: "Windows 10 Enterprise LTSC 2019", Edition: "EnterpriseS", Build: "17763.6532"}, "10-1809-e-lts"},
		{protocol.OSInfo{Family: "windows", Name: "Windows 11 Pro", DisplayVersion: "24H2", Edition: "Professional"}, "11-24h2-w,11-24h2"},
		{protocol.OSInfo{Family: "windows", Name: "Windows Server 2022 Standard", DisplayVersion: "21H2"}, ""},
	}
	for _, c := range cases {
		_, cands, _ := eolKey(c.os)
		if got := strings.Join(cands, ","); got != c.want {
			t.Errorf("%s: %q, want %q", c.os.Name, got, c.want)
		}
	}
	e := &EOLData{prods: map[string][]eolCycle{"windows": {{Cycle: "11-24h2-iot-lts", EOL: json.RawMessage(`"2034-10-10"`)}}}}
	if info, ok := e.Lookup(cases[0].os); !ok || info.IsEOL || info.EOL.Format("2006-01-02") != "2034-10-10" {
		t.Errorf("IoT LTSC lookup: %+v %v", info, ok)
	}
}
