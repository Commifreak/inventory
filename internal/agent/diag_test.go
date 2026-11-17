package agent

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

func TestDiagHandler(t *testing.T) {
	d := &diagLog{loaded: true} // in memory only
	d.entries = []protocol.AgentLogEntry{{Time: time.Now().Add(-40 * 24 * time.Hour), Level: "WARN", Message: "very old"}}
	var out bytes.Buffer
	log := slog.New(newDiagHandler(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelError}), d)).With("component", "test")

	log.Info("hello")
	log.Warn("report failed", "err", "server returned 502")
	log.WithGroup("upd").Error("update failed", "to", "1.2.3")

	got := d.recent()
	if len(got) != 2 {
		t.Fatalf("expected 2 recent entries (info and >30 days dropped), got %+v", got)
	}
	if got[0].Level != "WARN" || got[0].Message != "report failed component=test err=server returned 502" {
		t.Errorf("warn entry: %+v", got[0])
	}
	if got[1].Level != "ERROR" || got[1].Message != "update failed component=test upd.to=1.2.3" {
		t.Errorf("error entry: %+v", got[1])
	}
	// The wrapped handler keeps its own level: warnings are recorded but not printed.
	if strings.Contains(out.String(), "report failed") || !strings.Contains(out.String(), "update failed") {
		t.Errorf("wrapped handler output: %s", out.String())
	}
	for range 30 {
		log.Warn("again")
	}
	if n := len(d.recent()); n != diagMaxEntries {
		t.Errorf("buffer not capped: %d", n)
	}
}
