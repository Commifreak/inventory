package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Mailer sends notification mails (plain text plus optional HTML).
type Mailer interface {
	Send(ctx context.Context, to []string, m Mail) error
}

type smtpMailer struct{ s *Server }

func (m *smtpMailer) Send(ctx context.Context, to []string, msg Mail) error {
	cfg := m.s.smtpSettings(ctx)
	pw, err := m.s.secrets.Decrypt(cfg.PasswordEnc)
	if err != nil {
		return err
	}
	return sendMail(ctx, cfg, pw, to, msg)
}

func sendMail(ctx context.Context, cfg SMTPSettings, password string, to []string, msg Mail) error {
	if !cfg.Configured() {
		return errors.New("SMTP is not configured")
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return fmt.Errorf("invalid sender address: %w", err)
	}
	var rcpts []string
	for _, t := range to {
		a, err := mail.ParseAddress(strings.TrimSpace(t))
		if err != nil {
			return fmt.Errorf("invalid recipient %q", t)
		}
		rcpts = append(rcpts, a.Address)
	}
	if len(rcpts) == 0 {
		return errors.New("no recipients")
	}
	port := cfg.Port
	if port == 0 {
		port = map[string]int{"tls": 465, "none": 25}[cfg.Security]
		if port == 0 {
			port = 587
		}
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 20 * time.Second}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var conn net.Conn
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if cfg.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello(helloName()); err != nil {
		return err
	}
	if cfg.Security == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not support STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("server does not support authentication")
		}
		// smtp.PlainAuth refuses unencrypted connections except to localhost.
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, password, cfg.Host)); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("recipient %s rejected: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(buildMessage(from, rcpts, msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func helloName() string {
	return "inventory.localhost"
}

// buildMessage builds the mail: plain text only, or multipart/alternative
// with the HTML version. Bodies are quoted-printable (HTML lines can exceed
// the SMTP line length limit).
func buildMessage(from *mail.Address, to []string, msg Mail) []byte {
	var b strings.Builder
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("From", from.String())
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+randomToken(16)+"@inventory>")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	part := func(contentType, body string) {
		b.WriteString("Content-Type: " + contentType + "; charset=utf-8\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		var qp bytes.Buffer
		w := quotedprintable.NewWriter(&qp)
		_, _ = w.Write([]byte(strings.ReplaceAll(body, "\r\n", "\n")))
		_ = w.Close()
		b.Write(qp.Bytes())
		b.WriteString("\r\n")
	}
	if msg.HTML == "" {
		part("text/plain", msg.Text)
		return []byte(b.String())
	}
	boundary := "inv-" + randomToken(12)
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	b.WriteString("--" + boundary + "\r\n")
	part("text/plain", msg.Text)
	b.WriteString("--" + boundary + "\r\n")
	part("text/html", msg.HTML)
	b.WriteString("--" + boundary + "--\r\n")
	// The SMTP data writer converts line endings and dot-stuffs lines.
	return []byte(b.String())
}
