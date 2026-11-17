package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// EOLData provides end-of-support dates from endoflife.date, refreshed daily
// and cached in DATA_DIR/eol. A small built-in table covers Windows when the
// service cannot be reached.
type EOLData struct {
	dir   string
	fetch bool
	log   *slog.Logger
	mu    sync.RWMutex
	prods map[string][]eolCycle
	last  time.Time
}

type eolCycle struct {
	Cycle string          `json:"cycle"`
	EOL   json.RawMessage `json:"eol"` // date string or bool
}

// EOLInfo is the support status of an OS version.
type EOLInfo struct {
	Label string
	EOL   time.Time // zero if unknown
	IsEOL bool      // set when the source only says "true"
}

var eolProducts = []string{"windows", "debian", "ubuntu", "fedora", "rhel", "rocky-linux", "almalinux", "centos-stream", "opensuse", "linuxmint", "pop-os", "alpine", "macos"}

// Built-in fallback for Windows client releases (Home/Pro = w, Enterprise/Education = e).
var eolFallback = map[string][]eolCycle{
	"windows": {
		{"10-22h2-w", json.RawMessage(`"2025-10-14"`)}, {"10-22h2-e", json.RawMessage(`"2025-10-14"`)},
		{"11-21h2-w", json.RawMessage(`"2023-10-10"`)}, {"11-21h2-e", json.RawMessage(`"2024-10-08"`)},
		{"11-22h2-w", json.RawMessage(`"2024-10-08"`)}, {"11-22h2-e", json.RawMessage(`"2025-10-14"`)},
		{"11-23h2-w", json.RawMessage(`"2025-11-11"`)}, {"11-23h2-e", json.RawMessage(`"2026-11-10"`)},
		{"11-24h2-w", json.RawMessage(`"2026-10-13"`)}, {"11-24h2-e", json.RawMessage(`"2027-10-12"`)},
		{"11-25h2-w", json.RawMessage(`"2027-10-12"`)}, {"11-25h2-e", json.RawMessage(`"2028-10-10"`)},
	},
}

func newEOLData(dataDir string, fetch bool, log *slog.Logger) *EOLData {
	e := &EOLData{dir: filepath.Join(dataDir, "eol"), fetch: fetch, log: log, prods: map[string][]eolCycle{}}
	_ = os.MkdirAll(e.dir, 0o755)
	for _, p := range eolProducts {
		if b, err := os.ReadFile(filepath.Join(e.dir, p+".json")); err == nil {
			var c []eolCycle
			if json.Unmarshal(b, &c) == nil {
				e.prods[p] = c
			}
		}
	}
	return e
}

func (e *EOLData) loop(ctx context.Context) {
	if !e.fetch {
		return
	}
	for {
		e.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func (e *EOLData) refresh(ctx context.Context) {
	client := &http.Client{Timeout: 30 * time.Second}
	ok := 0
	for _, p := range eolProducts {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://endoflife.date/api/"+p+".json", nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "inventory-server")
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		var c []eolCycle
		if json.Unmarshal(b, &c) != nil || len(c) == 0 {
			continue
		}
		_ = os.WriteFile(filepath.Join(e.dir, p+".json"), b, 0o644)
		e.mu.Lock()
		e.prods[p] = c
		e.mu.Unlock()
		ok++
	}
	e.mu.Lock()
	e.last = time.Now()
	e.mu.Unlock()
	if ok == 0 {
		e.log.Warn("could not fetch end-of-life data from endoflife.date (using cached/built-in data)")
	}
}

func (e *EOLData) cycles(product string) []eolCycle {
	e.mu.RLock()
	c := e.prods[product]
	e.mu.RUnlock()
	if len(c) == 0 {
		c = eolFallback[product]
	}
	return c
}

func parseEOL(raw json.RawMessage) (time.Time, bool, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return time.Time{}, false, false
		}
		return t, t.Before(time.Now()), true
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return time.Time{}, b, true
	}
	return time.Time{}, false, false
}

// Lookup returns the support status of an OS. known is false when no data matches.
func (e *EOLData) Lookup(os protocol.OSInfo) (EOLInfo, bool) {
	product, candidates, label := eolKey(os)
	if product == "" {
		return EOLInfo{}, false
	}
	cyc := e.cycles(product)
	for _, cand := range candidates {
		for _, c := range cyc {
			if strings.EqualFold(c.Cycle, cand) {
				t, isEOL, ok := parseEOL(c.EOL)
				if !ok {
					return EOLInfo{}, false
				}
				return EOLInfo{Label: label, EOL: t, IsEOL: isEOL}, true
			}
		}
	}
	return EOLInfo{}, false
}

// eolKey maps an OS to an endoflife.date product and cycle candidates.
func eolKey(o protocol.OSInfo) (product string, cycles []string, label string) {
	switch o.Family {
	case protocol.OSWindows:
		if o.DisplayVersion == "" {
			return "", nil, ""
		}
		major := "10"
		if strings.Contains(o.Name, "Windows 11") {
			major = "11"
		}
		if strings.Contains(o.Name, "Server") || strings.Contains(o.Name, "LTSC") || strings.Contains(o.Name, "LTSB") {
			return "", nil, ""
		}
		ed := "w"
		low := strings.ToLower(o.Name + " " + o.Edition)
		if strings.Contains(low, "enterprise") || strings.Contains(low, "education") {
			ed = "e"
		}
		dv := strings.ToLower(o.DisplayVersion)
		return "windows", []string{major + "-" + dv + "-" + ed, major + "-" + dv}, fmt.Sprintf("Windows %s %s", major, o.DisplayVersion)
	case protocol.OSDarwin:
		v := strings.SplitN(o.Version, ".", 2)[0]
		return "macos", []string{v}, "macOS " + v
	case protocol.OSLinux:
		id := strings.ToLower(o.DistroID)
		m := map[string]string{"raspbian": "debian", "rocky": "rocky-linux", "opensuse-leap": "opensuse", "pop": "pop-os", "centos": "centos-stream"}
		if p, ok := m[id]; ok {
			id = p
		}
		known := false
		for _, p := range eolProducts {
			if p == id {
				known = true
			}
		}
		if !known || o.DistroVersion == "" {
			return "", nil, ""
		}
		v := o.DistroVersion
		parts := strings.Split(v, ".")
		cands := []string{v}
		if len(parts) > 2 {
			cands = append(cands, parts[0]+"."+parts[1])
		}
		if len(parts) > 1 {
			cands = append(cands, parts[0])
		}
		return id, cands, o.Name
	}
	return "", nil, ""
}
