package server

import (
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

func TestDiskView(t *testing.T) {
	dk := protocol.Disk{Device: "Disk 1", Model: "CT500MX500SSD1", Serial: "C1", HealthPassed: ptr(true), PercentUsed: ptr(124), CRCErrors: ptr(int64(4)), Reallocated: ptr(int64(0))}
	alerts := []store.Alert{
		{Rule: "smart_crc", Subject: "C1", Severity: SevWarning, State: store.AlertOpen},
		{Rule: "power_loss", Subject: "OTHER", Severity: SevCritical, State: store.AlertOpen},
		{Rule: "smart_temperature", Subject: "C1", Severity: SevCritical, State: store.AlertResolved},
	}
	now := time.Now()
	var hist []store.SmartPoint
	for i := 10; i >= 0; i-- {
		hist = append(hist, store.SmartPoint{Time: now.AddDate(0, 0, -i), Temperature: ptr(int64(30 + i%3)), Reallocated: ptr(int64(0)), CRCErrors: ptr(int64(4 - min(i, 4)))})
	}
	v := newDiskView(dk, alerts, hist)
	if v.Status != stWarning {
		t.Errorf("status %s", v.Status)
	}
	if is := v.Issue("wear"); is == nil || !strings.Contains(is.Reason, "beyond the rated endurance") {
		t.Errorf("wear issue: %+v", is)
	}
	if is := v.Issue("crc"); is == nil || !strings.Contains(is.Reason, "cable") {
		t.Errorf("crc issue from the open alert: %+v", is)
	}
	if v.Issue("unsafe") != nil || v.Issue("temperature") != nil || v.Issue("reallocated") != nil {
		t.Errorf("issues of other disks, resolved alerts or zero counters: %+v", v.Issues)
	}
	if len(v.Trends) != 2 || v.Trends[0].Name != "Temperature" || v.Trends[1].Name != "CRC errors" || strings.Join(v.Unchanged, ",") != "Reallocated" {
		t.Fatalf("trends %+v unchanged %v", v.Trends, v.Unchanged)
	}
	if s := v.Trends[1].Summary(); s != "+4 in 10 days" {
		t.Errorf("summary: %s", s)
	}
	if s := v.Trends[0].Summary(); s != "30–32 °C in 10 days" {
		t.Errorf("temperature summary: %s", s)
	}
	svg := string(trendChart(v.Trends[0]))
	// Axis at least 10 °C wide with whole-number labels, dates, tooltips.
	for _, want := range []string{`>36</text>`, `>31</text>`, `>26</text>`, now.Format("2 Jan") + `</text>`, "<title>" + now.Format("2006-01-02") + ": 30 °C</title>"} {
		if !strings.Contains(svg, want) {
			t.Errorf("chart lacks %q:\n%s", want, svg)
		}
	}
}
