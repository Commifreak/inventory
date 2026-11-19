package server

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/server/store"
)

func TestAlertMail(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.cfg.BaseURL = "https://inventory.example.com"
	ctx := t.Context()
	d := &store.Device{ID: "dev1", Hostname: "PC-01", OSName: "Windows 11 Pro", LastSeenAt: time.Now()}
	opened := []store.Alert{{Rule: "firewall_off", Severity: SevWarning, Message: "Firewall is off: <Public>.", OpenedAt: time.Now()}}
	resolved := []store.Alert{{Rule: "disk_space", Severity: SevCritical, Message: "Volume C: only 2% free.", OpenedAt: time.Now().Add(-time.Hour)}}
	m := s.alertMail(ctx, d, opened, resolved, nil)
	if !strings.Contains(m.Subject, "WARNING: PC-01: Firewall disabled") {
		t.Errorf("subject: %s", m.Subject)
	}
	if !strings.Contains(m.HTML, "Firewall is off: &lt;Public&gt;.") || !strings.Contains(m.HTML, "https://inventory.example.com/devices/dev1") ||
		!strings.Contains(m.HTML, "New alert, 1 resolved") || !strings.Contains(m.Text, "Volume C: only 2% free.") {
		t.Errorf("mail content incomplete:\n%s", m.Text)
	}
	if out := os.Getenv("MAIL_HTML"); out != "" {
		_ = os.WriteFile(out, []byte(m.HTML), 0o644)
	}

	// MIME structure: multipart/alternative with text and HTML.
	raw := buildMessage(&mail.Address{Address: "inv@example.com"}, []string{"a@example.com"}, m)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q %v", mt, err)
	}
	r := multipart.NewReader(msg.Body, params["boundary"])
	var types []string
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(p) // quoted-printable is decoded by the reader
		types = append(types, p.Header.Get("Content-Type"))
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") && !strings.Contains(string(body), "Open device in Inventory") {
			t.Error("HTML part not decoded correctly")
		}
	}
	if len(types) != 2 || !strings.HasPrefix(types[0], "text/plain") || !strings.HasPrefix(types[1], "text/html") {
		t.Errorf("parts: %v", types)
	}
	// Without HTML: a single text part.
	raw = buildMessage(&mail.Address{Address: "inv@example.com"}, []string{"a@example.com"}, Mail{Subject: "x", Text: "hello"})
	if msg, _ := mail.ReadMessage(bytes.NewReader(raw)); !strings.HasPrefix(msg.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("plain mail: %s", msg.Header.Get("Content-Type"))
	}
}
