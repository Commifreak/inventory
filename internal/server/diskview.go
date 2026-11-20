package server

import (
	"fmt"
	"html/template"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

// diskIssue explains why a value of a disk is highlighted.
type diskIssue struct {
	Severity string // warning, critical
	Reason   string // short, shown in the tile
}

// diskIssues returns the problems a disk reports by itself, keyed by the
// tile of the Disks tab they belong to.
func diskIssues(d protocol.Disk) map[string]diskIssue {
	m := map[string]diskIssue{}
	gt0 := func(p *int64) bool { return p != nil && *p > 0 }
	if d.HealthPassed != nil && !*d.HealthPassed {
		m["health"] = diskIssue{stCritical, "the drive reports that it is failing"}
	}
	if d.CriticalWarning != nil && *d.CriticalWarning != 0 {
		m["critical"] = diskIssue{stCritical, "NVMe warning flags set"}
	}
	if d.AvailableSpare != nil && d.SpareThreshold != nil && *d.SpareThreshold > 0 && *d.AvailableSpare <= *d.SpareThreshold {
		m["spare"] = diskIssue{stCritical, "reserve at or below the vendor threshold"}
	}
	if gt0(d.Reallocated) {
		m["reallocated"] = diskIssue{stWarning, "sectors were replaced by spare ones"}
	}
	if gt0(d.Pending) {
		m["pending"] = diskIssue{stWarning, "unstable sectors waiting to be remapped"}
	}
	if gt0(d.Uncorrectable) {
		m["uncorrectable"] = diskIssue{stWarning, "sectors could not be read"}
	}
	if gt0(d.MediaErrors) {
		m["media"] = diskIssue{stWarning, "unrecovered data integrity errors"}
	}
	if d.PercentUsed != nil && *d.PercentUsed >= 90 {
		r := "close to the rated endurance"
		if *d.PercentUsed > 100 {
			r = "beyond the rated endurance"
		}
		m["wear"] = diskIssue{stWarning, r}
	}
	return m
}

// DiskStatus classifies a disk by the problems it reports.
func DiskStatus(d protocol.Disk) string {
	st := stUnknown
	if d.HealthPassed != nil {
		st = stOK
	}
	for _, is := range diskIssues(d) {
		st = worse(st, is.Severity)
	}
	return st
}

// alertTiles maps the rules of open alerts of a disk to the tiles they
// highlight and a short reason. Rules covered by diskIssues are listed too:
// their thresholds can differ from the built-in ones.
var alertTiles = map[string]struct{ tile, reason string }{
	"smart_failed":        {"health", "the drive reports that it is failing"},
	"smart_reallocated":   {"reallocated", "new replaced sectors"},
	"smart_pending":       {"pending", "above the alert threshold"},
	"smart_uncorrectable": {"uncorrectable", "above the alert threshold"},
	"nvme_media_errors":   {"media", "new data integrity errors"},
	"smart_crc":           {"crc", "increasing – usually cable or connector"},
	"power_loss":          {"unsafe", "increasing – power cuts or hard power-offs"},
	"smart_temperature":   {"temperature", "at or above the alert threshold"},
	"nvme_wear":           {"wear", "at or above the alert threshold"},
	"nvme_critical":       {"spare", "reserve at or below the vendor threshold"},
}

// diskView is a disk as shown on the Disks tab.
type diskView struct {
	protocol.Disk
	Status    string
	Issues    map[string]diskIssue
	Trends    []trend
	Unchanged []string // names of counters without change in the history
}

// Issue returns the problem of a tile, or nil.
func (v diskView) Issue(tile string) *diskIssue {
	if is, ok := v.Issues[tile]; ok {
		return &is
	}
	return nil
}

func newDiskView(dk protocol.Disk, alerts []store.Alert, hist []store.SmartPoint) diskView {
	v := diskView{Disk: dk, Status: DiskStatus(dk), Issues: diskIssues(dk)}
	subj := diskSubject(dk)
	for _, a := range alerts {
		if a.State != store.AlertOpen || a.Subject != subj {
			continue
		}
		v.Status = worse(v.Status, a.Severity)
		if a.Rule == "smart_error_counters" {
			// One alert for three counters: highlight the ones it names.
			for tile, label := range map[string]string{"reported": "reported uncorrectable", "timeouts": "command timeouts", "spin": "spin retries"} {
				if strings.Contains(a.Message, label) {
					v.addIssue(tile, a.Severity, "increasing")
				}
			}
			continue
		}
		if t, ok := alertTiles[a.Rule]; ok {
			v.addIssue(t.tile, a.Severity, t.reason)
		}
	}
	v.Trends, v.Unchanged = diskTrends(hist)
	return v
}

// addIssue adds an alert's issue unless the disk itself reports a worse or
// equal one for the tile.
func (v *diskView) addIssue(tile, severity, reason string) {
	if cur, ok := v.Issues[tile]; ok && worse(cur.Severity, severity) == cur.Severity {
		return
	}
	v.Issues[tile] = diskIssue{severity, reason}
}

// trend is a value of a disk over time (one point per day).
type trend struct {
	Name, Unit string
	MinSpan    float64 // smallest value range of the axis, so noise does not look dramatic
	Points     []trendPoint
}

type trendPoint struct {
	T time.Time
	V float64
}

// diskTrends builds the charts of the SMART history. Series that did not
// change are returned by name only: a flat line says nothing.
func diskTrends(hist []store.SmartPoint) (charts []trend, unchanged []string) {
	series := []struct {
		name, unit string
		pick       func(store.SmartPoint) *int64
	}{
		{"Temperature", "°C", func(p store.SmartPoint) *int64 { return p.Temperature }},
		{"Wear (used)", "%", func(p store.SmartPoint) *int64 { return p.PercentUsed }},
		{"Available spare", "%", func(p store.SmartPoint) *int64 { return p.AvailableSpare }},
		// Counters below.
		{"Reallocated", "", func(p store.SmartPoint) *int64 { return p.Reallocated }},
		{"Pending", "", func(p store.SmartPoint) *int64 { return p.Pending }},
		{"Uncorrectable", "", func(p store.SmartPoint) *int64 { return p.Uncorrectable }},
		{"Media errors", "", func(p store.SmartPoint) *int64 { return p.MediaErrors }},
		{"CRC errors", "", func(p store.SmartPoint) *int64 { return p.CRCErrors }},
		{"Reported uncorrectable", "", func(p store.SmartPoint) *int64 { return p.ReportedUncorrect }},
		{"Command timeouts", "", func(p store.SmartPoint) *int64 { return p.CommandTimeout }},
		{"Spin retries", "", func(p store.SmartPoint) *int64 { return p.SpinRetry }},
		{"Unsafe shutdowns", "", func(p store.SmartPoint) *int64 { return p.UnsafeShutdowns }},
	}
	for _, s := range series {
		t := trend{Name: s.name, Unit: s.unit, MinSpan: 2}
		if s.unit != "" {
			t.MinSpan = 10
		}
		for _, p := range hist {
			if v := s.pick(p); v != nil {
				t.Points = append(t.Points, trendPoint{p.Time, float64(*v)})
			}
		}
		if len(t.Points) == 0 {
			continue
		}
		lo, hi := t.bounds()
		if lo == hi || len(t.Points) < 2 {
			unchanged = append(unchanged, s.name)
			continue
		}
		charts = append(charts, t)
	}
	return charts, unchanged
}

func (t trend) bounds() (lo, hi float64) {
	lo, hi = t.Points[0].V, t.Points[0].V
	for _, p := range t.Points {
		lo, hi = math.Min(lo, p.V), math.Max(hi, p.V)
	}
	return lo, hi
}

func fmtNum(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// trendChart renders a trend as an SVG line chart with a value axis (min,
// middle, max), the first and last date and a tooltip per day.
func trendChart(t trend) template.HTML {
	if len(t.Points) < 2 {
		return ""
	}
	const (
		w, h         = 300.0, 120.0
		left, right  = 40.0, 8.0
		top, bottom  = 8.0, 20.0
		plotW, plotH = w - left - right, h - top - bottom
	)
	// Axis: whole numbers, at least MinSpan wide around the values, with an
	// even span so the middle line is a whole number too.
	lo, hi := t.bounds()
	lo, hi = math.Floor(lo), math.Ceil(hi)
	if span := hi - lo; span < t.MinSpan {
		lo = math.Max(0, math.Floor(lo-(t.MinSpan-span)/2))
		hi = lo + t.MinSpan
	}
	if int(hi-lo)%2 == 1 {
		hi++
	}
	t0, t1 := t.Points[0].T, t.Points[len(t.Points)-1].T
	span := t1.Sub(t0).Seconds()
	if span <= 0 {
		span = 1
	}
	x := func(tm time.Time) float64 { return left + tm.Sub(t0).Seconds()/span*plotW }
	y := func(v float64) float64 { return top + (hi-v)/(hi-lo)*plotH }
	unit := t.Unit
	if unit != "" && unit != "%" {
		unit = " " + unit
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart" viewBox="0 0 %.0f %.0f" role="img" aria-label="%s, last 90 days">`, w, h, template.HTMLEscapeString(t.Name))
	mid := (lo + hi) / 2
	for _, v := range []float64{hi, mid, lo} {
		label := fmtNum(math.Round(v*10) / 10)
		fmt.Fprintf(&b, `<line class="grid" x1="%.1f" x2="%.1f" y1="%.1f" y2="%.1f"/><text class="ylab" x="%.1f" y="%.1f">%s</text>`,
			left, w-right, y(v), y(v), left-4, y(v)+3.5, label)
	}
	fmt.Fprintf(&b, `<text class="xlab" x="%.1f" y="%.1f">%s</text><text class="xlab end" x="%.1f" y="%.1f">%s</text>`,
		left, h-5, t0.Format("2 Jan"), w-right, h-5, t1.Format("2 Jan"))
	var pts []string
	for _, p := range t.Points {
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", x(p.T), y(p.V)))
	}
	fmt.Fprintf(&b, `<polyline points="%s"/>`, strings.Join(pts, " "))
	// One point per day: invisible until hovered (tooltip), the latest one shown.
	for i, p := range t.Points {
		cls := ""
		if i == len(t.Points)-1 {
			cls = ` class="last"`
		}
		fmt.Fprintf(&b, `<circle%s cx="%.1f" cy="%.1f" r="2.5"><title>%s: %s%s</title></circle>`,
			cls, x(p.T), y(p.V), p.T.Format("2006-01-02"), fmtNum(p.V), template.HTMLEscapeString(unit))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// Summary describes the period: the range for temperatures, the change for
// everything else.
func (t trend) Summary() string {
	if t.Unit == "°C" {
		lo, hi := t.bounds()
		return fmt.Sprintf("%s–%s °C in %d days", fmtNum(lo), fmtNum(hi), t.days())
	}
	return t.Change()
}

func (t trend) days() int {
	return int(math.Round(t.Points[len(t.Points)-1].T.Sub(t.Points[0].T).Hours() / 24))
}

// Change returns the difference between the last and the first value, e.g.
// "+3 in 90 days"; "" for no change.
func (t trend) Change() string {
	if len(t.Points) < 2 {
		return ""
	}
	d := t.Points[len(t.Points)-1].V - t.Points[0].V
	days := t.days()
	sign := "+"
	if d < 0 {
		sign = "−"
		d = -d
	}
	return fmt.Sprintf("%s%s in %d day%s", sign, fmtNum(d), days, map[bool]string{true: "", false: "s"}[days == 1])
}

// Last returns the latest value with unit.
func (t trend) Last() string {
	u := t.Unit
	if u != "" && u != "%" {
		u = " " + u
	}
	return fmtNum(t.Points[len(t.Points)-1].V) + u
}
