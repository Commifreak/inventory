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
	"regexp"
	"slices"
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
	api   string
	log   *slog.Logger
	mu    sync.RWMutex
	prods map[string][]eolCycle
	// lastOK is the last successful fetch (initialised from the cache files),
	// failures counts consecutive failed fetches, lastErr describes the last one.
	lastOK    time.Time
	failSince time.Time
	failures  int
	lastErr   string
}

const (
	eolRefreshInterval = 24 * time.Hour
	eolRetryInterval   = time.Hour
	// eolStaleAfter is how long fetching may fail before the UI warns.
	eolStaleAfter = 3 * 24 * time.Hour
)

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

var eolProducts = []string{"windows", "debian", "ubuntu", "fedora", "rhel", "rocky-linux", "almalinux", "centos-stream", "opensuse", "linuxmint", "pop-os", "alpine", "macos", "office"}

// Built-in fallback (Microsoft lifecycle dates) used when endoflife.date
// cannot be reached or does not list a cycle. Windows client releases:
// Home/Pro = w, Enterprise/Education = e. Office: end of (extended) support
// of the perpetual releases; Microsoft 365 Apps have no end date.
var eolFallback = map[string][]eolCycle{
	"windows": {
		{"10-22h2-w", json.RawMessage(`"2025-10-14"`)}, {"10-22h2-e", json.RawMessage(`"2025-10-14"`)},
		{"11-21h2-w", json.RawMessage(`"2023-10-10"`)}, {"11-21h2-e", json.RawMessage(`"2024-10-08"`)},
		{"11-22h2-w", json.RawMessage(`"2024-10-08"`)}, {"11-22h2-e", json.RawMessage(`"2025-10-14"`)},
		{"11-23h2-w", json.RawMessage(`"2025-11-11"`)}, {"11-23h2-e", json.RawMessage(`"2026-11-10"`)},
		{"11-24h2-w", json.RawMessage(`"2026-10-13"`)}, {"11-24h2-e", json.RawMessage(`"2027-10-12"`)},
		{"11-25h2-w", json.RawMessage(`"2027-10-12"`)}, {"11-25h2-e", json.RawMessage(`"2028-10-10"`)},
		{"11-26h1-w", json.RawMessage(`"2028-03-14"`)}, {"11-26h1-e", json.RawMessage(`"2029-03-13"`)},
		{"11-26h2-w", json.RawMessage(`"2028-10-10"`)}, {"11-26h2-e", json.RawMessage(`"2029-10-09"`)},
	},
	"office": {
		{"2007", json.RawMessage(`"2017-10-10"`)}, {"2010", json.RawMessage(`"2020-10-13"`)},
		{"2013", json.RawMessage(`"2023-04-11"`)}, {"2016", json.RawMessage(`"2025-10-14"`)},
		{"2019", json.RawMessage(`"2025-10-14"`)}, {"2021", json.RawMessage(`"2026-10-13"`)},
		{"2024", json.RawMessage(`"2029-10-09"`)},
	},
}

func newEOLData(dataDir string, fetch bool, log *slog.Logger) *EOLData {
	e := &EOLData{dir: filepath.Join(dataDir, "eol"), fetch: fetch, api: "https://endoflife.date/api/", log: log, prods: map[string][]eolCycle{}}
	_ = os.MkdirAll(e.dir, 0o755)
	for _, p := range eolProducts {
		f := filepath.Join(e.dir, p+".json")
		if b, err := os.ReadFile(f); err == nil {
			var c []eolCycle
			if json.Unmarshal(b, &c) == nil {
				e.prods[p] = c
				if fi, err := os.Stat(f); err == nil && fi.ModTime().After(e.lastOK) {
					e.lastOK = fi.ModTime()
				}
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
		wait := eolRefreshInterval
		if !e.refresh(ctx) {
			wait = eolRetryInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// refresh fetches all products; it reports whether endoflife.date answered.
func (e *EOLData) refresh(ctx context.Context) bool {
	client := &http.Client{Timeout: 30 * time.Second}
	ok := 0
	var firstErr string
	fail := func(msg string) {
		if firstErr == "" {
			firstErr = msg
		}
	}
	for _, p := range eolProducts {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.api+p+".json", nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "inventory-server")
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return true // shutting down, not a failure
			}
			fail(err.Error())
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			fail(err.Error())
			continue
		}
		if resp.StatusCode != http.StatusOK {
			fail(fmt.Sprintf("%s: HTTP %d", p, resp.StatusCode))
			continue
		}
		var c []eolCycle
		if json.Unmarshal(b, &c) != nil || len(c) == 0 {
			fail(p + ": unexpected response")
			continue
		}
		_ = os.WriteFile(filepath.Join(e.dir, p+".json"), b, 0o644)
		e.mu.Lock()
		e.prods[p] = c
		e.mu.Unlock()
		ok++
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ok > 0 {
		e.lastOK, e.failures, e.lastErr, e.failSince = time.Now(), 0, "", time.Time{}
		return true
	}
	if e.failures == 0 {
		e.failSince = time.Now()
	}
	e.failures++
	e.lastErr = firstErr
	e.log.Warn("could not fetch end-of-life data from endoflife.date (using cached/built-in data)", "err", firstErr, "attempts", e.failures)
	return false
}

// Warning returns a message for the UI when end-of-support data could not be
// fetched for a longer time, or never since the installation.
func (e *EOLData) Warning(now time.Time) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.fetch || e.failures == 0 {
		return ""
	}
	if e.lastOK.IsZero() {
		if e.failures < 2 {
			return ""
		}
		return fmt.Sprintf("End-of-support data could not be fetched from endoflife.date since %s (%s). Only the built-in dates for Windows and Office are used; Linux and macOS are not checked. Allow outbound HTTPS to endoflife.date or set EOL_FETCH=false.",
			e.failSince.Format("2006-01-02 15:04"), e.lastErr)
	}
	if now.Sub(e.lastOK) < eolStaleAfter {
		return ""
	}
	return fmt.Sprintf("End-of-support data could not be fetched from endoflife.date since %s (%s). Data cached on %s is used and may be outdated.",
		e.failSince.Format("2006-01-02 15:04"), e.lastErr, e.lastOK.Format("2006-01-02"))
}

func (e *EOLData) cycles(product string) []eolCycle {
	e.mu.RLock()
	c := e.prods[product]
	e.mu.RUnlock()
	return c
}

// lookupCycle finds the first candidate cycle, preferring the fetched data
// and falling back to the built-in table.
func (e *EOLData) lookupCycle(product string, candidates []string) (t time.Time, isEOL, ok bool) {
	for _, cyc := range [][]eolCycle{e.cycles(product), eolFallback[product]} {
		for _, cand := range candidates {
			for _, c := range cyc {
				if strings.EqualFold(c.Cycle, cand) {
					return parseEOL(c.EOL)
				}
			}
		}
	}
	return time.Time{}, false, false
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
	t, isEOL, ok := e.lookupCycle(product, candidates)
	if !ok {
		return EOLInfo{}, false
	}
	return EOLInfo{Label: label, EOL: t, IsEOL: isEOL}, true
}

// OfficeEOL is the support status of an installed Office release.
type OfficeEOL struct {
	Cycle    string   // release year, e.g. "2021"
	Products []string // installed product names of that release
	EOLInfo
}

// officeName matches perpetual Office, Visio and Project releases by their
// uninstall name, e.g. "Microsoft Office LTSC Professional Plus 2021 - de-de",
// "Microsoft Office Home and Business 2019", "Microsoft Visio Standard 2016".
var officeName = regexp.MustCompile(`(?i)^microsoft (office|visio|project)\b.*\b(2007|2010|2013|2016|2019|2021|2024)\b`)

// officeIgnore skips components that are not the product itself.
var officeIgnore = regexp.MustCompile(`(?i)365|add-?in|proofing|language|mui|runtime|click-to-run|web components|shared|validation`)

// OfficeLookup returns the support status of the Office releases found in a
// software inventory, one entry per release year.
func (e *EOLData) OfficeLookup(items []protocol.SoftwareItem) []OfficeEOL {
	var out []OfficeEOL
	idx := map[string]int{}
	for _, it := range items {
		m := officeName.FindStringSubmatch(it.Name)
		if m == nil || officeIgnore.MatchString(it.Name) {
			continue
		}
		year := m[2]
		if i, ok := idx[year]; ok {
			if !slices.Contains(out[i].Products, it.Name) {
				out[i].Products = append(out[i].Products, it.Name)
			}
			continue
		}
		t, isEOL, ok := e.lookupCycle("office", []string{year, year + "-ltsc", "ltsc-" + year})
		if !ok {
			continue
		}
		idx[year] = len(out)
		out = append(out, OfficeEOL{Cycle: year, Products: []string{it.Name}, EOLInfo: EOLInfo{Label: "Office " + year, EOL: t, IsEOL: isEOL}})
	}
	slices.SortFunc(out, func(a, b OfficeEOL) int { return strings.Compare(a.Cycle, b.Cycle) })
	return out
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
