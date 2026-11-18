package server

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

//go:embed web/templates/*.html web/static/*
var webFS embed.FS

type webUI struct {
	s     *Server
	pages map[string]*template.Template
}

func newWebUI(s *Server) (*webUI, error) {
	w := &webUI{s: s, pages: map[string]*template.Template{}}
	funcs := template.FuncMap{
		"ago":     timeAgo,
		"fmtTime": fmtTime,
		"fmtDate": fmtDate,
		"bytes":   func(v uint64) string { return humanBytes(v) },
		"bytesI":  func(v int64) string { return humanBytes(uint64(v)) },
		"pct": func(a, b uint64) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b) * 100
		},
		"deref":  deref,
		"derefB": func(b *bool) bool { return b != nil && *b },
		"isSet":  func(b *bool) bool { return b != nil },
		"join":   strings.Join,
		"lower":  strings.ToLower,
		"upper":  strings.ToUpper,
		"title": func(s string) string {
			if s == "" {
				return s
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
		"json": func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) },
		"prettyJSON": func(raw json.RawMessage) string {
			var buf bytes.Buffer
			if len(raw) == 0 || json.Indent(&buf, raw, "", "  ") != nil {
				return string(raw)
			}
			return buf.String()
		},
		"toJSON": func(v any) string {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return err.Error()
			}
			return string(b)
		},
		"logLevelClass": func(level string) string {
			if strings.HasPrefix(level, "ERROR") {
				return "st-critical"
			}
			return "st-warning"
		},
		"installedModules": func(ms []protocol.MemoryModule) int {
			n := 0
			for _, m := range ms {
				if m.Installed {
					n++
				}
			}
			return n
		},
		"storageSlots": func(sl []protocol.SystemSlot) []protocol.SystemSlot {
			var out []protocol.SystemSlot
			for _, x := range sl {
				if x.Kind == "storage" {
					out = append(out, x)
				}
			}
			return out
		},
		"add": func(a, b int) int { return a + b },
		"div": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"contains":  strings.Contains,
		"hasPrefix": strings.HasPrefix,
		"durHours":  func(sec int) float64 { return float64(sec) / 3600 },
		"fnum": func(f float64) string {
			if f == math.Trunc(f) {
				return fmt.Sprintf("%.0f", f)
			}
			return fmt.Sprintf("%g", f)
		},
		"ruleCatalog": func() []RuleDef { return RuleCatalog },
		"hasString":   func(list []string, v string) bool { return slices.Contains(list, v) },
		"hasID":       func(list []int64, v int64) bool { return slices.Contains(list, v) },
		"ruleTitle": func(id string) string {
			if d := ruleDef(id); d != nil {
				return d.Title
			}
			return id
		},
		"sparkline": sparkline,
		"dict":      dict,
		"seq": func(n int) []int {
			s := make([]int, n)
			for i := range s {
				s[i] = i
			}
			return s
		},
		"since":      func(t time.Time) time.Duration { return time.Since(t) },
		"daysSince":  func(t time.Time) int { return int(time.Since(t).Hours() / 24) },
		"collectors": func() []string { return protocol.AllCollectors },
		"rings":      func() []string { return Rings },
		"volUsed": func(v protocol.Volume) float64 {
			if v.SizeBytes == 0 {
				return 0
			}
			return float64(v.SizeBytes-v.FreeBytes) / float64(v.SizeBytes) * 100
		},
	}
	layout, err := fs.ReadFile(webFS, "web/templates/layout.html")
	if err != nil {
		return nil, err
	}
	partials, err := fs.ReadFile(webFS, "web/templates/partials.html")
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(webFS, "web/templates")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if name == "layout.html" || name == "partials.html" {
			continue
		}
		body, err := fs.ReadFile(webFS, "web/templates/"+name)
		if err != nil {
			return nil, err
		}
		t := template.New("layout").Funcs(funcs)
		for _, src := range [][]byte{layout, partials, body} {
			if _, err := t.Parse(string(src)); err != nil {
				return nil, fmt.Errorf("template %s: %w", name, err)
			}
		}
		w.pages[strings.TrimSuffix(name, ".html")] = t
	}
	return w, nil
}

// page is the data passed to every template.
type page struct {
	Title    string
	Nav      string
	User     *store.User
	CSRF     string
	Flash    string
	Error    string
	Version  string
	Instance string
	OIDC     bool
	OIDCName string
	Local    bool
	// Warnings are server problems shown to signed-in users on every page.
	Warnings []string
	// Super: the user is a superadmin. AreaNames: names of the visible areas;
	// MultiArea: more than one is visible (area column and filter are shown).
	Super     bool
	AreaNames map[int64]string
	Areas     []store.Area
	MultiArea bool
	Data      any
}

func (w *webUI) render(rw http.ResponseWriter, r *http.Request, name string, p page) {
	t, ok := w.pages[name]
	if !ok {
		http.Error(rw, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	if p.User == nil {
		p.User = userFrom(r.Context())
	}
	if sess := sessionFrom(r.Context()); sess != nil {
		p.CSRF = sess.CSRF
	}
	p.Version = w.s.cfg.Version
	p.Instance = w.s.generalSettings(r.Context()).InstanceName
	if acc := accessFrom(r.Context()); acc != nil {
		p.Super = acc.Super
		p.Areas = w.s.visibleAreas(r.Context())
		p.AreaNames = map[int64]string{}
		for _, a := range p.Areas {
			p.AreaNames[a.ID] = a.Name
		}
		p.MultiArea = len(p.Areas) > 1
	}
	if p.User != nil {
		if msg := w.s.eol.Warning(time.Now()); msg != "" {
			p.Warnings = append(p.Warnings, msg)
		}
	}
	p.OIDC = w.s.cfg.OIDC.Enabled()
	p.OIDCName = w.s.cfg.OIDC.ButtonLabel
	p.Local = w.s.cfg.LocalLogin
	if p.Flash == "" {
		p.Flash = r.URL.Query().Get("flash")
	}
	if p.Error == "" {
		p.Error = r.URL.Query().Get("error")
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		w.s.log.Error("render", "page", name, "err", err)
		http.Error(rw, "template error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(rw)
}

func redirectFlash(w http.ResponseWriter, r *http.Request, to, flash string) {
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	http.Redirect(w, r, to+sep+"flash="+urlQuery(flash), http.StatusSeeOther)
}

func redirectError(w http.ResponseWriter, r *http.Request, to, msg string) {
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	http.Redirect(w, r, to+sep+"error="+urlQuery(msg), http.StatusSeeOther)
}

func urlQuery(s string) string { return template.URLQueryEscaper(s) }

// ---------------------------------------------------------------------------
// template helpers
// ---------------------------------------------------------------------------

func timeAgo(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < 0 {
		d = -d
		return "in " + humanDuration(d)
	}
	if d < time.Minute {
		return "just now"
	}
	return humanDuration(d) + " ago"
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.In(time.Local).Format("2006-01-02 15:04")
}

func fmtDate(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.In(time.Local).Format("2006-01-02")
}

func deref(v any) any {
	switch p := v.(type) {
	case *int:
		if p == nil {
			return "–"
		}
		return *p
	case *int64:
		if p == nil {
			return "–"
		}
		return *p
	case *float64:
		if p == nil {
			return "–"
		}
		return fmt.Sprintf("%.2f", *p)
	case *bool:
		if p == nil {
			return "–"
		}
		if *p {
			return "yes"
		}
		return "no"
	}
	return v
}

func dict(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string)
		m[k] = kv[i+1]
	}
	return m
}

// sparkline renders a small inline SVG polyline for a series.
func sparkline(vals []float64) template.HTML {
	if len(vals) < 2 {
		return ""
	}
	min, max := vals[0], vals[0]
	for _, v := range vals {
		min = math.Min(min, v)
		max = math.Max(max, v)
	}
	if max == min {
		max = min + 1
	}
	const w, h = 160.0, 32.0
	var pts []string
	for i, v := range vals {
		x := float64(i) / float64(len(vals)-1) * w
		y := h - 2 - (v-min)/(max-min)*(h-4)
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", x, y))
	}
	return template.HTML(fmt.Sprintf(`<svg class="spark" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none" aria-hidden="true"><polyline points="%s"/></svg>`, w, h, strings.Join(pts, " ")))
}

// ---------------------------------------------------------------------------
// status computation shared by list and detail views
// ---------------------------------------------------------------------------

// Status levels, ordered.
const (
	stUnknown  = "unknown"
	stOK       = "ok"
	stWarning  = "warning"
	stCritical = "critical"
)

func worse(a, b string) string {
	rank := map[string]int{stUnknown: 0, stOK: 1, stWarning: 2, stCritical: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// DiskStatus classifies a disk.
func DiskStatus(d protocol.Disk) string {
	if d.HealthPassed != nil && !*d.HealthPassed {
		return stCritical
	}
	if d.CriticalWarning != nil && *d.CriticalWarning != 0 {
		return stCritical
	}
	gt0 := func(p *int64) bool { return p != nil && *p > 0 }
	if gt0(d.Reallocated) || gt0(d.Pending) || gt0(d.Uncorrectable) || gt0(d.MediaErrors) {
		return stWarning
	}
	if d.PercentUsed != nil && *d.PercentUsed >= 90 {
		return stWarning
	}
	if d.HealthPassed != nil {
		return stOK
	}
	return stUnknown
}

// DeviceRow is the dashboard view of a device.
type DeviceRow struct {
	D             store.Device
	Online        string // online, stale, offline, never
	OSName        string
	SysDisk       *protocol.Disk
	SysDiskStatus string
	DiskStatus    string
	DiskCount     int
	Pending       int
	Security      int
	UpdatesKnown  bool
	FailedUpdates int
	Reboot        bool
	SearchError   string
	Alerts        int
	AlertSev      string
	AgentLatest   string    // newest signed agent for the platform, if newer than the installed one
	LastReport    time.Time // latest collector data received
	Overall       string
	Duplicates    []store.Device // same hardware in other areas (superadmins only)
}

func (s *Server) onlineState(d *store.Device, now time.Time, checkin int) string {
	if d.LastSeenAt.IsZero() {
		return "never"
	}
	age := now.Sub(d.LastSeenAt)
	switch {
	case age <= time.Duration(checkin*2+120)*time.Second:
		return "online"
	case age <= 24*time.Hour:
		return "stale"
	}
	return "offline"
}

func (s *Server) deviceRow(d store.Device, snaps map[string]*store.Snapshot, alerts []store.Alert, now time.Time, checkin int) DeviceRow {
	row := DeviceRow{D: d, Online: s.onlineState(&d, now, checkin), OSName: d.OSName, DiskStatus: stUnknown, SysDiskStatus: stUnknown}
	if smart, ok := decodeSnap[protocol.SmartData](snaps, protocol.CollectSMART); ok {
		for i := range smart.Disks {
			dk := smart.Disks[i]
			if dk.External {
				continue
			}
			row.DiskCount++
			st := DiskStatus(dk)
			row.DiskStatus = worse(row.DiskStatus, st)
			if dk.System && row.SysDisk == nil {
				row.SysDisk = &smart.Disks[i]
				row.SysDiskStatus = st
			}
		}
	}
	if up, ok := decodeSnap[protocol.UpdatesData](snaps, protocol.CollectUpdates); ok {
		row.UpdatesKnown = true
		row.Pending, row.Security, row.Reboot, row.SearchError = up.PendingCount, up.SecurityCount, up.RebootRequired, up.SearchError
		latest := map[string]protocol.UpdateHistoryEntry{}
		for _, h := range up.History {
			if cur, ok := latest[h.Title]; !ok || h.Date.After(cur.Date) {
				latest[h.Title] = h
			}
		}
		for _, h := range latest {
			if (h.Result == "Failed" || h.Result == "Aborted") && now.Sub(h.Date) < 30*24*time.Hour {
				row.FailedUpdates++
			}
		}
	}
	row.AlertSev = stOK
	for _, a := range alerts {
		if a.DeviceID == d.ID && a.State == store.AlertOpen {
			row.Alerts++
			row.AlertSev = worse(row.AlertSev, a.Severity)
		}
	}
	row.Overall = row.AlertSev
	if row.Alerts == 0 {
		row.Overall = worse(stOK, row.DiskStatus)
		if row.DiskStatus == stUnknown {
			row.Overall = stOK
		}
	}
	return row
}

func sortRows(rows []DeviceRow, by string) {
	rank := map[string]int{stCritical: 0, stWarning: 1, stUnknown: 2, stOK: 3}
	sort.SliceStable(rows, func(i, j int) bool {
		switch by {
		case "status":
			if rank[rows[i].Overall] != rank[rows[j].Overall] {
				return rank[rows[i].Overall] < rank[rows[j].Overall]
			}
		case "seen":
			return rows[i].D.LastSeenAt.After(rows[j].D.LastSeenAt)
		case "report":
			return rows[i].LastReport.After(rows[j].LastReport)
		}
		return strings.ToLower(rows[i].D.Name()) < strings.ToLower(rows[j].D.Name())
	})
}
