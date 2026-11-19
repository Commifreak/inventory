package server

import (
	"bytes"
	"html/template"
)

// Mail is a notification with a plain text and an HTML body.
type Mail struct {
	Subject string
	Text    string
	HTML    string // optional
}

// mailAlert is one alert line of a notification mail.
type mailAlert struct {
	Title    string
	Message  string
	Severity string // warning, critical, resolved
	Since    string
}

type mailSection struct {
	Title  string
	Alerts []mailAlert
}

type mailData struct {
	Instance string
	Heading  string
	Severity string // critical, warning, resolved: colour of the heading
	Device   string
	Rows     [][2]string // label, value
	Sections []mailSection
	URL      string
}

// Mail clients ignore most CSS: layout tables and inline styles only. The
// dark colours apply in clients that support prefers-color-scheme.
var alertMailTmpl = template.Must(template.New("mail").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{{.Heading}}</title>
<style>
@media (prefers-color-scheme: dark) {
  .bg { background: #0f141b !important; }
  .card { background: #171d26 !important; border-color: #2a3441 !important; }
  .text { color: #e5e9f0 !important; }
  .muted { color: #96a0b0 !important; }
  .box { background: #1e2631 !important; }
  .row { border-top-color: #2a3441 !important; border-right-color: #2a3441 !important; border-bottom-color: #2a3441 !important; }
}
</style>
</head>
<body class="bg" style="margin:0;padding:0;background:#f5f6f8;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="bg" style="background:#f5f6f8;">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:600px;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <tr><td class="muted" style="padding:0 4px 10px;font-size:13px;color:#677284;font-weight:600;">{{.Instance}}</td></tr>
  <tr><td class="card" style="background:#ffffff;border:1px solid #dfe3ea;border-radius:10px;overflow:hidden;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
      <tr><td style="height:5px;line-height:5px;font-size:0;background:{{if eq .Severity "critical"}}#b91c1c{{else if eq .Severity "warning"}}#d97706{{else}}#15803d{{end}};">&nbsp;</td></tr>
      <tr><td style="padding:22px 24px 6px;">
        <div class="text" style="font-size:20px;line-height:1.3;font-weight:700;color:#1c2330;">{{.Heading}}</div>
        <div class="text" style="font-size:16px;line-height:1.4;color:#1c2330;margin-top:4px;">{{.Device}}</div>
      </td></tr>
      <tr><td style="padding:12px 24px 4px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="box" style="background:#f0f2f5;border-radius:8px;">
          {{range .Rows}}<tr><td class="muted" style="padding:6px 12px;font-size:13px;color:#677284;width:90px;vertical-align:top;">{{index . 0}}</td><td class="text" style="padding:6px 12px;font-size:13px;color:#1c2330;">{{index . 1}}</td></tr>{{end}}
        </table>
      </td></tr>
      {{range .Sections}}
      <tr><td style="padding:18px 24px 2px;">
        <div class="muted" style="font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#677284;">{{.Title}}</div>
      </td></tr>
      {{range .Alerts}}
      <tr><td style="padding:8px 24px 0;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="row" style="border:1px solid #dfe3ea;border-left:4px solid {{if eq .Severity "critical"}}#b91c1c{{else if eq .Severity "warning"}}#d97706{{else}}#15803d{{end}};border-radius:6px;">
          <tr><td style="padding:10px 12px;">
            <span style="display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;{{if eq .Severity "critical"}}background:#fee2e2;color:#b91c1c;{{else if eq .Severity "warning"}}background:#fef3c7;color:#a16207;{{else}}background:#dcfce7;color:#15803d;{{end}}">{{.Severity}}</span>
            <span class="text" style="font-size:15px;font-weight:600;color:#1c2330;padding-left:6px;">{{.Title}}</span>
            <div class="text" style="font-size:14px;line-height:1.45;color:#1c2330;margin-top:6px;">{{.Message}}</div>
            <div class="muted" style="font-size:12px;color:#677284;margin-top:4px;">{{.Since}}</div>
          </td></tr>
        </table>
      </td></tr>
      {{end}}{{end}}
      {{if .URL}}
      <tr><td style="padding:22px 24px 4px;">
        <a href="{{.URL}}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:10px 18px;border-radius:6px;">Open device in Inventory</a>
      </td></tr>
      {{end}}
      <tr><td style="padding:18px 24px 22px;"></td></tr>
    </table>
  </td></tr>
  <tr><td class="muted" style="padding:12px 4px;font-size:12px;color:#677284;text-align:center;">Sent by Inventory – read-only monitoring. Notification settings are managed in the Inventory web UI.</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
`))

func renderMailHTML(d mailData) string {
	var buf bytes.Buffer
	if err := alertMailTmpl.Execute(&buf, d); err != nil {
		return ""
	}
	return buf.String()
}
