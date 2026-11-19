package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

// Event alerts get no reminders; events received after the last
// notification are mailed instead.
func TestEventAlertNotifications(t *testing.T) {
	s, ts, fm := newTestServer(t)
	ctx := context.Background()
	_ = s.store.PutSetting(ctx, setSMTP, SMTPSettings{Host: "localhost", From: "inv@example.com", Port: 25})
	as := s.alertSettings(ctx)
	as.Recipients = []string{"admin@example.com"}
	as.RenotifyHours = 24
	_ = s.store.PutSetting(ctx, setAlerts, as)
	toks, _ := s.store.ListTokens(ctx)
	er := enroll(t, ts, toks[0].Token, protocol.Identity{Hostname: "PC", OS: "windows", Arch: "amd64", HardwareID: "HW"})

	addEvent := func(key, msg string, at time.Time) {
		t.Helper()
		tx, err := s.store.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.store.AddEvent(ctx, tx, store.Event{DeviceID: er.DeviceID, Key: key, Kind: protocol.EventAutostartAdded, Time: at, Message: msg, ReceivedAt: at}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	alert := func() store.Alert {
		t.Helper()
		open, _ := s.store.OpenAlertsForDevice(ctx, er.DeviceID)
		for _, a := range open {
			if a.Rule == "autostart_added" {
				return a
			}
		}
		t.Fatal("no open autostart alert")
		return store.Alert{}
	}
	sent := func() []Mail {
		var out []Mail
		for _, m := range fm.mails {
			if strings.Contains(m.Subject, "New autostart entry") {
				out = append(out, m)
			}
		}
		return out
	}

	// Opened 30 hours ago and notified then.
	old := time.Now().Add(-30 * time.Hour)
	addEvent("a1", "New autostart entry: Updater A", old)
	s.runAlerts(ctx, nil)
	if n := len(sent()); n != 1 {
		t.Fatalf("mails after opening: %d", n)
	}
	a := alert()
	if _, err := s.store.DB.ExecContext(ctx, `UPDATE alerts SET last_notified_at=? WHERE id=?`, old.Unix(), a.ID); err != nil {
		t.Fatal(err)
	}

	// The reminder interval has passed: no reminder for an event alert.
	s.runAlerts(ctx, nil)
	if n := len(sent()); n != 1 {
		t.Fatalf("event alert was repeated as reminder: %d mails", n)
	}

	// A new event while the alert is open: mail with only the new entry.
	addEvent("a2", "New autostart entry: Updater B", time.Now())
	s.runAlerts(ctx, nil)
	m := sent()
	if len(m) != 2 {
		t.Fatalf("no mail for the new event: %d mails", len(m))
	}
	last := m[1]
	if !strings.Contains(last.Text, "New events") || !strings.Contains(last.Text, "Since the last notification: 1 new autostart entry/entries. New autostart entry: Updater B") ||
		strings.Contains(last.Text, "Updater A") || !strings.Contains(last.Text, "2 in the last 168 hours in total.") {
		t.Errorf("new-events mail:\n%s", last.Text)
	}
	if a := alert(); a.NotifyCount != 2 || !strings.Contains(a.Message, "Updater A") || !strings.Contains(a.Message, "Updater B") {
		t.Errorf("alert after new event: count %d, message %q", a.NotifyCount, a.Message)
	}

	// Nothing new: no further mail.
	s.runAlerts(ctx, nil)
	if n := len(sent()); n != 2 {
		t.Errorf("mail without new events: %d mails", n)
	}
}

// SSD wear gets no reminders, but a mail every further 10 percentage points.
func TestWearAlertSteps(t *testing.T) {
	s, ts, fm := newTestServer(t)
	ctx := context.Background()
	_ = s.store.PutSetting(ctx, setSMTP, SMTPSettings{Host: "localhost", From: "inv@example.com", Port: 25})
	as := s.alertSettings(ctx)
	as.Recipients = []string{"admin@example.com"}
	as.RenotifyHours = 24
	_ = s.store.PutSetting(ctx, setAlerts, as)
	toks, _ := s.store.ListTokens(ctx)
	er := enroll(t, ts, toks[0].Token, protocol.Identity{Hostname: "PC", OS: "windows", Arch: "amd64", HardwareID: "HW"})
	report := func(used int) {
		t.Helper()
		rep := protocol.Report{AgentVersion: "0.0.9", Sections: map[string]protocol.Section{protocol.CollectSMART: {CollectedAt: time.Now(), Data: protocol.SmartData{Disks: []protocol.Disk{
			{Device: "Disk 0", Model: "CT500MX500SSD1", Serial: "C1", Protocol: "ATA", HealthPassed: ptr(true), Reallocated: ptr(int64(0)), PercentUsed: ptr(used)}}}}}}
		if code := postJSON(t, ts.URL+protocol.APIPrefix+"/report", er.Credential, rep, nil); code != 200 {
			t.Fatalf("report: %d", code)
		}
		s.runAlerts(ctx, nil)
	}
	wear := func() []Mail {
		var out []Mail
		for _, m := range fm.mails {
			if strings.Contains(m.Subject, "SSD wear") {
				out = append(out, m)
			}
		}
		return out
	}
	alert := func() store.Alert {
		t.Helper()
		open, _ := s.store.OpenAlertsForDevice(ctx, er.DeviceID)
		for _, a := range open {
			if a.Rule == "nvme_wear" {
				return a
			}
		}
		t.Fatal("no open wear alert")
		return store.Alert{}
	}

	report(92)
	if n := len(wear()); n != 1 {
		t.Fatalf("mails after crossing the threshold: %d", n)
	}
	// Reminder interval passed, value within the same step: no mail.
	_, _ = s.store.DB.ExecContext(ctx, `UPDATE alerts SET last_notified_at=?`, time.Now().Add(-30*time.Hour).Unix())
	report(99)
	if n := len(wear()); n != 1 {
		t.Fatalf("wear alert repeated within a step: %d mails", n)
	}
	// Next step reached.
	report(100)
	m := wear()
	if len(m) != 2 || !strings.Contains(m[1].Text, "Alert increased") || !strings.Contains(m[1].Text, "100% of rated endurance used. Previously notified at 92%.") {
		t.Fatalf("step mail: %d mails\n%s", len(m), m[len(m)-1].Text)
	}
	if a := alert(); a.NotifiedValue == nil || *a.NotifiedValue != 100 {
		t.Errorf("notified value: %v", a.NotifiedValue)
	}
	report(109)
	if n := len(wear()); n != 2 {
		t.Errorf("mail within the step 100–109: %d mails", n)
	}
	report(127)
	m = wear()
	if len(m) != 3 || !strings.Contains(m[2].Text, "127% of rated endurance used – beyond the manufacturer's rating, no errors reported so far. Previously notified at 100%.") {
		t.Errorf("mail beyond rating: %d mails\n%s", len(m), m[len(m)-1].Text)
	}
}
