package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

func (w *webUI) routes(mux *http.ServeMux) {
	s := w.s
	static, _ := fs.Sub(webFS, "web/static")
	fileServer := http.StripPrefix("/static/", http.FileServer(http.FS(static)))
	mux.Handle("GET /static/", http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "public, max-age=3600")
		fileServer.ServeHTTP(rw, r)
	}))

	mux.HandleFunc("GET /login", w.handleLoginPage)
	mux.HandleFunc("POST /login", w.handleLogin)
	mux.HandleFunc("POST /logout", s.requireUser(w.handleLogout))
	if s.oidc != nil {
		mux.HandleFunc("GET /auth/oidc/login", s.oidc.handleLogin)
		mux.HandleFunc("GET /auth/oidc/callback", s.oidc.handleCallback)
	}
	mux.HandleFunc("GET /account/password", s.requireUser(w.handlePasswordPage))
	mux.HandleFunc("POST /account/password", s.requireUser(w.handlePasswordChange))

	mux.HandleFunc("GET /{$}", s.requireUser(w.handleDashboard))
	mux.HandleFunc("GET /devices/{id}", s.requireUser(w.handleDevice))
	mux.HandleFunc("GET /devices/{id}/raw.json", s.requireUser(w.handleDeviceRaw))
	mux.HandleFunc("POST /devices/{id}/settings", s.requireUser(w.handleDeviceSettings))
	mux.HandleFunc("POST /devices/{id}/update-now", s.requireUser(w.handleDeviceUpdateNow))
	mux.HandleFunc("POST /devices/{id}/collect", s.requireUser(w.handleDeviceCollect))
	mux.HandleFunc("POST /devices/{id}/revoke", s.requireUser(w.handleDeviceRevoke))
	mux.HandleFunc("POST /devices/{id}/delete", s.requireUser(w.handleDeviceDelete))
	mux.HandleFunc("POST /devices/bulk", s.requireUser(w.handleDevicesBulk))
	mux.HandleFunc("GET /alerts", s.requireUser(w.handleAlerts))

	mux.HandleFunc("GET /settings", s.requireUser(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, "/settings/install", http.StatusSeeOther)
	}))
	mux.HandleFunc("GET /settings/install", s.requireUser(w.handleInstallPage))
	mux.HandleFunc("POST /settings/tokens", s.requireUser(w.handleTokenCreate))
	mux.HandleFunc("POST /settings/tokens/{id}/revoke", s.requireUser(w.handleTokenRevoke))
	mux.HandleFunc("GET /downloads/windows/{token}/{arch}", s.requireUser(w.handleWindowsDownload))
	mux.HandleFunc("GET /settings/updates", s.requireUser(w.handleUpdatesPage))
	mux.HandleFunc("POST /settings/updates", s.requireUser(w.handleUpdatesSave))
	mux.HandleFunc("POST /settings/updates/promote", s.requireUser(w.handleUpdatesPromote))
	mux.HandleFunc("GET /settings/collection", s.requireUser(w.handleCollectionPage))
	mux.HandleFunc("POST /settings/collection", s.requireUser(w.handleCollectionSave))
	mux.HandleFunc("GET /settings/alerts", s.requireUser(w.handleAlertSettingsPage))
	mux.HandleFunc("POST /settings/alerts", s.requireUser(w.handleAlertSettingsSave))
	mux.HandleFunc("GET /settings/smtp", s.requireUser(w.handleSMTPPage))
	mux.HandleFunc("POST /settings/smtp", s.requireUser(w.handleSMTPSave))
	mux.HandleFunc("POST /settings/smtp/test", s.requireUser(w.handleSMTPTest))
	mux.HandleFunc("GET /settings/users", s.requireUser(w.handleUsersPage))
	mux.HandleFunc("POST /settings/users", s.requireUser(w.handleUserCreate))
	mux.HandleFunc("POST /settings/users/{id}/{action}", s.requireUser(w.handleUserAction))
	mux.HandleFunc("GET /settings/general", s.requireUser(w.handleGeneralPage))
	mux.HandleFunc("POST /settings/general", s.requireUser(w.handleGeneralSave))
}

func actor(r *http.Request) string {
	if u := userFrom(r.Context()); u != nil {
		return u.Username
	}
	return ""
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

func (w *webUI) renderLogin(rw http.ResponseWriter, r *http.Request, errMsg string) {
	w.render(rw, r, "login", page{Title: "Sign in", Error: errMsg, Data: map[string]string{"Next": safeNext(r.URL.Query().Get("next"))}})
}

func (w *webUI) handleLoginPage(rw http.ResponseWriter, r *http.Request) {
	if u, _ := w.s.loadSession(r); u != nil {
		http.Redirect(rw, r, "/", http.StatusSeeOther)
		return
	}
	w.renderLogin(rw, r, "")
}

func (w *webUI) handleLogin(rw http.ResponseWriter, r *http.Request) {
	s := w.s
	if !s.cfg.LocalLogin {
		http.Error(rw, "local login is disabled", http.StatusForbidden)
		return
	}
	ip := s.clientIP(r)
	username := strings.TrimSpace(r.PostFormValue("username"))
	if !s.limiter.allow("login:"+ip, 10, 2) || !s.limiter.allow("loginuser:"+strings.ToLower(username), 10, 2) {
		w.renderLogin(rw, r, "Too many login attempts. Please wait a few minutes.")
		return
	}
	u, err := s.store.UserByName(r.Context(), username)
	pw := r.PostFormValue("password")
	if err != nil {
		_ = checkPassword(string(dummyHash), pw)
		s.log.Warn("login failed", "user", username, "ip", ip)
		w.renderLogin(rw, r, "Invalid user name or password.")
		return
	}
	if u.Disabled || !checkPassword(u.PasswordHash, pw) {
		s.log.Warn("login failed", "user", username, "ip", ip)
		w.renderLogin(rw, r, "Invalid user name or password.")
		return
	}
	if err := s.newSession(rw, r, u); err != nil {
		w.renderLogin(rw, r, "Could not create session.")
		return
	}
	s.store.Audit(r.Context(), u.Username, "login", ip)
	next := safeNext(r.PostFormValue("next"))
	if u.MustChangePassword {
		next = "/account/password"
	}
	http.Redirect(rw, r, next, http.StatusSeeOther)
}

func (w *webUI) handleLogout(rw http.ResponseWriter, r *http.Request) {
	w.s.clearSession(rw, r)
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (w *webUI) handlePasswordPage(rw http.ResponseWriter, r *http.Request) {
	w.render(rw, r, "password", page{Title: "Change password", Nav: "account"})
}

func (w *webUI) handlePasswordChange(rw http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if u.PasswordHash == "" {
		redirectError(rw, r, "/account/password", "This account signs in via single sign-on and has no local password.")
		return
	}
	if !checkPassword(u.PasswordHash, r.PostFormValue("current")) {
		redirectError(rw, r, "/account/password", "The current password is wrong.")
		return
	}
	pw := r.PostFormValue("new")
	if pw != r.PostFormValue("confirm") {
		redirectError(rw, r, "/account/password", "The new passwords do not match.")
		return
	}
	if err := validatePassword(pw); err != nil {
		redirectError(rw, r, "/account/password", err.Error())
		return
	}
	if pw == r.PostFormValue("current") {
		redirectError(rw, r, "/account/password", "Please choose a new password.")
		return
	}
	hash, err := hashPassword(pw)
	if err != nil {
		redirectError(rw, r, "/account/password", "internal error")
		return
	}
	_ = w.s.store.SetPassword(r.Context(), u.ID, hash, false)
	_ = w.s.store.DeleteUserSessions(r.Context(), u.ID, sessionFrom(r.Context()).IDHash)
	w.s.store.Audit(r.Context(), u.Username, "password.changed", "")
	redirectFlash(rw, r, "/", "Password changed.")
}

// ---------------------------------------------------------------------------
// dashboard
// ---------------------------------------------------------------------------

func (w *webUI) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	s := w.s
	ctx := r.Context()
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	snaps, _ := s.store.AllSnapshots(ctx, protocol.CollectSMART, protocol.CollectUpdates)
	alerts, _ := s.store.OpenAlerts(ctx)
	now := time.Now()
	checkin := s.collectionConfig(ctx).CheckinIntervalSec
	var rows []DeviceRow
	counts := map[string]int{}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	problems := r.URL.Query().Get("problems") == "1"
	for _, d := range devices {
		row := s.deviceRow(d, snaps[d.ID], alerts, now, checkin)
		if latest := s.agents.Latest(d.OS, d.Arch, true); latest != "" && CompareVersions(latest, d.AgentVersion) > 0 {
			row.AgentLatest = latest
		}
		counts["total"]++
		counts[row.Online]++
		counts[row.Overall]++
		if q != "" && !strings.Contains(strings.ToLower(d.Name()+" "+d.Hostname+" "+d.OSName+" "+d.LastIP), q) {
			continue
		}
		if problems && row.Overall == stOK && row.Online == "online" {
			continue
		}
		rows = append(rows, row)
	}
	sortBy := r.URL.Query().Get("sort")
	if sortBy == "" {
		sortBy = "status"
	}
	sortRows(rows, sortBy)
	w.render(rw, r, "dashboard", page{Title: "Devices", Nav: "devices", Data: map[string]any{
		"Rows": rows, "Counts": counts, "Q": r.URL.Query().Get("q"), "Problems": problems, "Sort": sortBy,
		"OpenAlerts": len(alerts), "Versions": s.agents.Versions(),
	}})
}

// ---------------------------------------------------------------------------
// device detail
// ---------------------------------------------------------------------------

type diskView struct {
	protocol.Disk
	Status string
	Trends map[string][]float64
}

func (w *webUI) loadDevice(rw http.ResponseWriter, r *http.Request) *store.Device {
	d, err := w.s.store.DeviceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		http.NotFound(rw, r)
		return nil
	}
	return d
}

func (w *webUI) handleDevice(rw http.ResponseWriter, r *http.Request) {
	s := w.s
	ctx := r.Context()
	d := w.loadDevice(rw, r)
	if d == nil {
		return
	}
	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "overview"
	}
	snaps, _ := s.store.Snapshots(ctx, d.ID)
	alerts, _ := s.store.DeviceAlerts(ctx, d.ID, 100)
	now := time.Now()
	row := s.deviceRow(*d, snaps, alerts, now, s.collectionConfig(ctx).CheckinIntervalSec)
	data := map[string]any{"D": d, "Row": row, "Tab": tab, "Snaps": snaps, "Alerts": alerts}

	if sys, ok := decodeSnap[protocol.SystemInfo](snaps, protocol.CollectSystem); ok {
		data["Sys"] = sys
		if info, known := s.eol.Lookup(sys.OS); known {
			data["EOL"] = info
		}
	}
	switch tab {
	case "disks":
		if smart, ok := decodeSnap[protocol.SmartData](snaps, protocol.CollectSMART); ok {
			var disks []diskView
			for _, dk := range smart.Disks {
				dv := diskView{Disk: dk, Status: DiskStatus(dk), Trends: map[string][]float64{}}
				if dk.Serial != "" {
					hist, _ := s.store.SmartHistory(ctx, d.ID, dk.Serial, now.AddDate(0, 0, -90))
					for _, p := range hist {
						addTrend(dv.Trends, "Temperature", p.Temperature)
						addTrend(dv.Trends, "Reallocated", p.Reallocated)
						addTrend(dv.Trends, "Pending", p.Pending)
						addTrend(dv.Trends, "Percent used", p.PercentUsed)
						addTrend(dv.Trends, "Media errors", p.MediaErrors)
					}
				}
				disks = append(disks, dv)
			}
			sort.SliceStable(disks, func(i, j int) bool { return disks[i].System && !disks[j].System })
			data["Smart"] = smart
			data["Disks"] = disks
		}
	case "updates":
		if up, ok := decodeSnap[protocol.UpdatesData](snaps, protocol.CollectUpdates); ok {
			data["Updates"] = up
		}
	case "software":
		if sw, ok := decodeSnap[protocol.SoftwareData](snaps, protocol.CollectSoftware); ok {
			sort.Slice(sw.Items, func(i, j int) bool { return strings.ToLower(sw.Items[i].Name) < strings.ToLower(sw.Items[j].Name) })
			data["Software"] = sw
			data["Office"] = s.eol.OfficeLookup(sw.Items)
		}
		changes, _ := s.store.SoftwareChanges(ctx, d.ID, 300)
		data["Changes"] = changes
	case "autostart":
		if as, ok := decodeSnap[protocol.AutostartData](snaps, protocol.CollectAutostart); ok {
			sort.SliceStable(as.Items, func(i, j int) bool {
				if as.Items[i].Location != as.Items[j].Location {
					return as.Items[i].Location < as.Items[j].Location
				}
				return strings.ToLower(as.Items[i].Name) < strings.ToLower(as.Items[j].Name)
			})
			data["Autostart"] = as
		}
	case "events":
		ev, _ := s.store.Events(ctx, d.ID, now.AddDate(0, 0, -365), 500)
		data["Events"] = ev
	case "agent":
		target, reason := TargetVersion(d, s.updatePolicy(ctx), s.agents)
		data["Target"], data["TargetReason"] = target, reason
		data["Versions"] = s.agents.Versions()
		data["Latest"] = s.agents.Latest(d.OS, d.Arch, true)
		logs, _ := s.store.ListAgentUpdates(ctx, d.ID, 30)
		data["UpdateLog"] = logs
		data["Config"] = s.collectionConfig(ctx)
		data["OfflineDefault"] = s.alertSettings(ctx).Rules["offline"].Params["hours"]
		if diag, _ := s.store.GetAgentDiagnostics(ctx, d.ID); diag != nil {
			data["Diag"] = diag
			rev := slices.Clone(diag.Data.Log)
			slices.Reverse(rev)
			data["DiagLog"] = rev
		}
	case "raw":
		data["Diag"], _ = s.store.GetAgentDiagnostics(ctx, d.ID)
	}
	w.render(rw, r, "device", page{Title: d.Name(), Nav: "devices", Data: data})
}

// handleDeviceRaw exports everything known about a device as JSON (diagnostics).
func (w *webUI) handleDeviceRaw(rw http.ResponseWriter, r *http.Request) {
	d := w.loadDevice(rw, r)
	if d == nil {
		return
	}
	ctx := r.Context()
	snaps, _ := w.s.store.Snapshots(ctx, d.ID)
	events, _ := w.s.store.Events(ctx, d.ID, time.Now().AddDate(0, 0, -90), 1000)
	diag, _ := w.s.store.GetAgentDiagnostics(ctx, d.ID)
	type section struct {
		CollectedAt time.Time       `json:"collected_at"`
		DurationMs  int64           `json:"duration_ms"`
		Error       string          `json:"error,omitempty"`
		Warnings    []string        `json:"warnings,omitempty"`
		Data        json.RawMessage `json:"data,omitempty"`
	}
	out := struct {
		Exported time.Time          `json:"exported"`
		Server   string             `json:"server_version"`
		Device   map[string]any     `json:"device"`
		Sections map[string]section `json:"sections"`
		Events   []store.Event      `json:"events"`
		// AgentDiagnostics: proxy and latest agent warnings/errors.
		AgentDiagnostics *store.AgentDiagnostics `json:"agent_diagnostics,omitempty"`
	}{Exported: time.Now().UTC(), Server: w.s.cfg.Version, Sections: map[string]section{}, Events: events, AgentDiagnostics: diag,
		Device: map[string]any{"id": d.ID, "hostname": d.Hostname, "os": d.OS, "arch": d.Arch, "agent_version": d.AgentVersion,
			"enrolled_at": d.EnrolledAt, "last_seen_at": d.LastSeenAt, "ring": d.Ring, "update_state": d.UpdateState, "update_error": d.UpdateError}}
	for name, sn := range snaps {
		out.Sections[name] = section{CollectedAt: sn.CollectedAt, DurationMs: sn.DurationMs, Error: sn.Error, Warnings: sn.Warnings, Data: sn.Data}
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="inventory-%s-%s.json"`, safeFile(d.Hostname), time.Now().Format("20060102-1504")))
	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func safeFile(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func addTrend(m map[string][]float64, key string, v *int64) {
	if v != nil {
		m[key] = append(m[key], float64(*v))
	}
}

func (w *webUI) handleDeviceSettings(rw http.ResponseWriter, r *http.Request) {
	d := w.loadDevice(rw, r)
	if d == nil {
		return
	}
	ring := r.PostFormValue("ring")
	if !slices.Contains(Rings, ring) {
		ring = RingStable
	}
	ds := store.DeviceSettings{
		DisplayName:   strings.TrimSpace(r.PostFormValue("display_name")),
		Notes:         strings.TrimSpace(r.PostFormValue("notes")),
		Ring:          ring,
		PinnedVersion: r.PostFormValue("pinned_version"),
		AlertsMuted:   r.PostFormValue("alerts_muted") == "1",
	}
	if v := strings.TrimSpace(r.PostFormValue("offline_alert_hours")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			redirectError(rw, r, "/devices/"+d.ID+"?tab=agent", "Offline alert must be a number of hours (0 = disabled).")
			return
		}
		ds.OfflineAlertHours = sql.NullInt64{Int64: int64(n), Valid: true}
	}
	if err := w.s.store.UpdateDeviceSettings(r.Context(), d.ID, ds); err != nil {
		redirectError(rw, r, "/devices/"+d.ID+"?tab=agent", err.Error())
		return
	}
	w.s.store.Audit(r.Context(), actor(r), "device.settings", d.ID)
	w.s.kickAlerts(d.ID)
	redirectFlash(rw, r, "/devices/"+d.ID+"?tab=agent", "Settings saved.")
}

func (w *webUI) handleDeviceUpdateNow(rw http.ResponseWriter, r *http.Request) {
	d := w.loadDevice(rw, r)
	if d == nil {
		return
	}
	v := r.PostFormValue("version")
	if v == "" {
		v = w.s.agents.Latest(d.OS, d.Arch, true)
	}
	if b, _, ok := w.s.agents.Binary(v, d.OS, d.Arch); !ok || b.Signature == "" {
		redirectError(rw, r, "/devices/"+d.ID+"?tab=agent", "No signed agent "+v+" available for "+d.OS+"/"+d.Arch+".")
		return
	}
	_ = w.s.store.SetUpdateNow(r.Context(), d.ID, v)
	_ = w.s.store.SetUpdateState(r.Context(), d.ID, v, "", "")
	w.s.store.Audit(r.Context(), actor(r), "device.update_now", d.ID+" -> "+v)
	redirectFlash(rw, r, "/devices/"+d.ID+"?tab=agent", "The agent will update to "+v+" at its next check-in.")
}

func (w *webUI) handleDeviceCollect(rw http.ResponseWriter, r *http.Request) {
	d := w.loadDevice(rw, r)
	if d == nil {
		return
	}
	_ = w.s.store.SetCollectNow(r.Context(), d.ID, strings.Join(protocol.AllCollectors, ","))
	redirectFlash(rw, r, "/devices/"+d.ID+"?tab="+urlQuery(r.PostFormValue("tab")), "All data will be collected at the next check-in.")
}

func (w *webUI) handleDeviceRevoke(rw http.ResponseWriter, r *http.Request) {
	d := w.loadDevice(rw, r)
	if d == nil {
		return
	}
	_ = w.s.store.RevokeDevice(r.Context(), d.ID)
	w.s.store.Audit(r.Context(), actor(r), "device.revoked", d.ID+" "+d.Hostname)
	redirectFlash(rw, r, "/devices/"+d.ID+"?tab=agent", "Device revoked. The agent stops reporting; reinstalling it re-enrolls the device.")
}

func (w *webUI) handleDeviceDelete(rw http.ResponseWriter, r *http.Request) {
	d := w.loadDevice(rw, r)
	if d == nil {
		return
	}
	_ = w.s.store.DeleteDevice(r.Context(), d.ID)
	w.s.store.Audit(r.Context(), actor(r), "device.deleted", d.ID+" "+d.Hostname)
	redirectFlash(rw, r, "/", "Device "+d.Name()+" deleted.")
}

func (w *webUI) handleDevicesBulk(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	ids := r.PostForm["ids"]
	action := r.PostFormValue("action")
	if len(ids) == 0 {
		redirectError(rw, r, "/", "No devices selected.")
		return
	}
	n := 0
	for _, id := range ids {
		d, err := w.s.store.DeviceByID(ctx, id)
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(action, "ring:"):
			ring := strings.TrimPrefix(action, "ring:")
			if slices.Contains(Rings, ring) {
				_ = w.s.store.SetDeviceRing(ctx, id, ring)
				n++
			}
		case action == "update":
			if v := w.s.agents.Latest(d.OS, d.Arch, true); v != "" {
				_ = w.s.store.SetUpdateNow(ctx, id, v)
				n++
			}
		case action == "collect":
			_ = w.s.store.SetCollectNow(ctx, id, strings.Join(protocol.AllCollectors, ","))
			n++
		}
	}
	w.s.store.Audit(ctx, actor(r), "devices.bulk", fmt.Sprintf("%s on %d devices", action, n))
	redirectFlash(rw, r, "/", fmt.Sprintf("Applied to %d device(s).", n))
}

// ---------------------------------------------------------------------------
// alerts
// ---------------------------------------------------------------------------

func (w *webUI) handleAlerts(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	alerts, _ := w.s.store.RecentAlerts(ctx, 500)
	devices, _ := w.s.store.ListDevices(ctx)
	names := map[string]string{}
	for _, d := range devices {
		names[d.ID] = d.Name()
	}
	w.render(rw, r, "alerts", page{Title: "Alerts", Nav: "alerts", Data: map[string]any{"Alerts": alerts, "Names": names, "SMTP": w.s.smtpSettings(ctx).Configured()}})
}

// ---------------------------------------------------------------------------
// settings: install & tokens
// ---------------------------------------------------------------------------

func (w *webUI) handleInstallPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	toks, _ := w.s.store.ListTokens(ctx)
	latest := map[string]string{}
	for _, p := range []string{"windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64", "linux/arm", "darwin/arm64", "darwin/amd64"} {
		goos, goarch, _ := strings.Cut(p, "/")
		latest[p] = w.s.agents.Latest(goos, goarch, false)
	}
	w.render(rw, r, "settings_install", page{Title: "Install agents", Nav: "settings", Data: map[string]any{
		"Tokens": toks, "BaseURL": w.s.baseURL(r), "BaseURLSet": w.s.cfg.BaseURL != "", "APIPrefix": protocol.APIPrefix, "Latest": latest,
	}})
}

func (w *webUI) handleTokenCreate(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		name = "Token " + time.Now().Format("2006-01-02")
	}
	if _, err := w.s.store.CreateToken(r.Context(), randomToken(24), truncate(name, 100)); err != nil {
		redirectError(rw, r, "/settings/install", err.Error())
		return
	}
	w.s.store.Audit(r.Context(), actor(r), "token.created", name)
	redirectFlash(rw, r, "/settings/install", "Enrollment token created.")
}

func (w *webUI) handleTokenRevoke(rw http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = w.s.store.RevokeToken(r.Context(), id)
	w.s.store.Audit(r.Context(), actor(r), "token.revoked", strconv.FormatInt(id, 10))
	redirectFlash(rw, r, "/settings/install", "Token revoked. Installers containing it no longer enroll new devices; enrolled devices keep working.")
}

func (w *webUI) handleWindowsDownload(rw http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("token"), 10, 64)
	tok, err := w.s.store.TokenByID(r.Context(), id)
	if err != nil || !tok.Active() {
		http.Error(rw, "token not found or revoked", http.StatusNotFound)
		return
	}
	arch := r.PathValue("arch")
	if arch != "amd64" && arch != "arm64" {
		http.NotFound(rw, r)
		return
	}
	w.s.writeWindowsInstaller(rw, r, tok, arch)
}

// ---------------------------------------------------------------------------
// settings: agent updates
// ---------------------------------------------------------------------------

func (w *webUI) handleUpdatesPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devices, _ := w.s.store.ListDevices(ctx)
	byVersion := map[string]int{}
	byRing := map[string]int{}
	for _, d := range devices {
		byVersion[d.AgentVersion]++
		byRing[d.Ring]++
	}
	w.render(rw, r, "settings_updates", page{Title: "Agent updates", Nav: "settings", Data: map[string]any{
		"Policy": w.s.updatePolicy(ctx), "Versions": w.s.agents.Versions(), "ByVersion": byVersion, "ByRing": byRing, "Latest": w.s.agents.LatestAny(),
	}})
}

func (w *webUI) handleUpdatesSave(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := w.s.updatePolicy(ctx)
	p.Paused = r.PostFormValue("paused") == "1"
	for _, ring := range Rings {
		v := r.PostFormValue("ring_" + ring)
		if v != "" {
			if len(w.s.agents.Versions()) > 0 && !w.versionExists(v) {
				redirectError(rw, r, "/settings/updates", "Unknown version "+v)
				return
			}
		}
		p.RingVersions[ring] = v
	}
	if err := w.s.store.PutSetting(ctx, setUpdates, p); err != nil {
		redirectError(rw, r, "/settings/updates", err.Error())
		return
	}
	w.s.store.Audit(ctx, actor(r), "updates.policy", fmt.Sprintf("paused=%v rings=%v", p.Paused, p.RingVersions))
	redirectFlash(rw, r, "/settings/updates", "Update policy saved.")
}

// handleUpdatesPromote sets a ring to a concrete version (e.g. "promote latest to early").
func (w *webUI) handleUpdatesPromote(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ring, v := r.PostFormValue("ring"), r.PostFormValue("version")
	if !slices.Contains(Rings, ring) || (v != "" && !w.versionExists(v)) {
		redirectError(rw, r, "/settings/updates", "Invalid ring or version.")
		return
	}
	p := w.s.updatePolicy(ctx)
	p.RingVersions[ring] = v
	_ = w.s.store.PutSetting(ctx, setUpdates, p)
	w.s.store.Audit(ctx, actor(r), "updates.promote", ring+" -> "+v)
	label := v
	if label == "" {
		label = "latest"
	}
	redirectFlash(rw, r, "/settings/updates", "Ring "+ring+" now follows "+label+".")
}

func (w *webUI) versionExists(v string) bool {
	for _, m := range w.s.agents.Versions() {
		if m.Version == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// settings: collection
// ---------------------------------------------------------------------------

func (w *webUI) handleCollectionPage(rw http.ResponseWriter, r *http.Request) {
	w.render(rw, r, "settings_collection", page{Title: "Data collection", Nav: "settings", Data: map[string]any{"Config": w.s.collectionConfig(r.Context()), "Defaults": protocol.DefaultConfig()}})
}

func (w *webUI) handleCollectionSave(rw http.ResponseWriter, r *http.Request) {
	c := protocol.AgentConfig{Intervals: map[string]int{}}
	mins, err := strconv.Atoi(r.PostFormValue("checkin_minutes"))
	if err != nil || mins < 1 || mins > 1440 {
		redirectError(rw, r, "/settings/collection", "Check-in interval must be between 1 and 1440 minutes.")
		return
	}
	c.CheckinIntervalSec = mins * 60
	for _, name := range protocol.AllCollectors {
		if r.PostFormValue("enabled_"+name) != "1" {
			c.Intervals[name] = 0
			continue
		}
		h, err := strconv.ParseFloat(r.PostFormValue("hours_"+name), 64)
		if err != nil || h < 0.25 || h > 24*30 {
			redirectError(rw, r, "/settings/collection", "Interval for "+name+" must be between 0.25 and 720 hours.")
			return
		}
		c.Intervals[name] = int(h * 3600)
	}
	_ = w.s.store.PutSetting(r.Context(), setCollection, c)
	w.s.store.Audit(r.Context(), actor(r), "collection.saved", "")
	redirectFlash(rw, r, "/settings/collection", "Saved. Agents pick up the new settings at their next check-in.")
}

// ---------------------------------------------------------------------------
// settings: alerts
// ---------------------------------------------------------------------------

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == ' ' || r == '\r' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (w *webUI) handleAlertSettingsPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groups := []string{}
	for _, d := range RuleCatalog {
		if !slices.Contains(groups, d.Group) {
			groups = append(groups, d.Group)
		}
	}
	w.render(rw, r, "settings_alerts", page{Title: "Alert rules", Nav: "settings", Data: map[string]any{
		"Settings": w.s.alertSettings(ctx), "Catalog": RuleCatalog, "Groups": groups, "SMTP": w.s.smtpSettings(ctx).Configured(),
	}})
}

func (w *webUI) handleAlertSettingsSave(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	as := w.s.alertSettings(ctx)
	as.Recipients = splitList(r.PostFormValue("recipients"))
	as.NotifyResolved = r.PostFormValue("notify_resolved") == "1"
	if n, err := strconv.Atoi(r.PostFormValue("renotify_hours")); err == nil && n >= 0 {
		as.RenotifyHours = n
	}
	for _, def := range RuleCatalog {
		rc := as.Rules[def.ID]
		rc.Enabled = r.PostFormValue("en_"+def.ID) == "1"
		if sev := r.PostFormValue("sev_" + def.ID); sev == SevWarning || sev == SevCritical {
			rc.Severity = sev
		}
		rc.SystemDiskOnly = def.DiskScope && r.PostFormValue("sys_"+def.ID) == "1"
		rc.IncludeExternal = def.ExternalOption && r.PostFormValue("ext_"+def.ID) == "1"
		rc.Recipients = splitList(r.PostFormValue("rcpt_" + def.ID))
		for _, p := range def.Params {
			v, err := strconv.ParseFloat(strings.ReplaceAll(r.PostFormValue("p_"+def.ID+"_"+p.Key), ",", "."), 64)
			if err != nil || v < 0 {
				redirectError(rw, r, "/settings/alerts", "Invalid value for "+def.Title+" / "+p.Label)
				return
			}
			rc.Params[p.Key] = v
		}
		as.Rules[def.ID] = rc
	}
	if err := w.s.store.PutSetting(ctx, setAlerts, as); err != nil {
		redirectError(rw, r, "/settings/alerts", err.Error())
		return
	}
	w.s.store.Audit(ctx, actor(r), "alerts.saved", "")
	w.s.kickAlerts("")
	redirectFlash(rw, r, "/settings/alerts", "Alert rules saved.")
}

// ---------------------------------------------------------------------------
// settings: SMTP
// ---------------------------------------------------------------------------

func (w *webUI) handleSMTPPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.render(rw, r, "settings_smtp", page{Title: "E-mail (SMTP)", Nav: "settings", Data: map[string]any{
		"SMTP": w.s.smtpSettings(ctx), "Recipients": strings.Join(w.s.alertSettings(ctx).Recipients, ", "),
	}})
}

func (w *webUI) smtpFromForm(r *http.Request) (SMTPSettings, error) {
	cur := w.s.smtpSettings(r.Context())
	c := SMTPSettings{
		Host:     strings.TrimSpace(r.PostFormValue("host")),
		Security: r.PostFormValue("security"),
		Username: strings.TrimSpace(r.PostFormValue("username")),
		From:     strings.TrimSpace(r.PostFormValue("from")),
	}
	if c.Security != "tls" && c.Security != "none" {
		c.Security = "starttls"
	}
	port, err := strconv.Atoi(r.PostFormValue("port"))
	if err != nil || port < 1 || port > 65535 {
		return c, errors.New("invalid port")
	}
	c.Port = port
	switch pw := r.PostFormValue("password"); {
	case r.PostFormValue("clear_password") == "1":
		c.PasswordEnc = ""
	case pw != "":
		enc, err := w.s.secrets.Encrypt(pw)
		if err != nil {
			return c, err
		}
		c.PasswordEnc = enc
	default:
		c.PasswordEnc = cur.PasswordEnc
	}
	return c, nil
}

func (w *webUI) handleSMTPSave(rw http.ResponseWriter, r *http.Request) {
	c, err := w.smtpFromForm(r)
	if err != nil {
		redirectError(rw, r, "/settings/smtp", err.Error())
		return
	}
	_ = w.s.store.PutSetting(r.Context(), setSMTP, c)
	w.s.store.Audit(r.Context(), actor(r), "smtp.saved", c.Host)
	redirectFlash(rw, r, "/settings/smtp", "SMTP settings saved.")
}

func (w *webUI) handleSMTPTest(rw http.ResponseWriter, r *http.Request) {
	c := w.s.smtpSettings(r.Context())
	to := splitList(r.PostFormValue("to"))
	if len(to) == 0 {
		redirectError(rw, r, "/settings/smtp", "Please enter a recipient for the test mail.")
		return
	}
	pw, err := w.s.secrets.Decrypt(c.PasswordEnc)
	if err == nil {
		err = sendMail(r.Context(), c, pw, to, "["+w.s.generalSettings(r.Context()).InstanceName+"] Test mail",
			"This is a test mail from your Inventory server.\n\nIf you can read this, alert mails will be delivered.\n")
	}
	if err != nil {
		redirectError(rw, r, "/settings/smtp", "Sending failed: "+err.Error())
		return
	}
	redirectFlash(rw, r, "/settings/smtp", "Test mail sent to "+strings.Join(to, ", ")+".")
}

// ---------------------------------------------------------------------------
// settings: users
// ---------------------------------------------------------------------------

func (w *webUI) handleUsersPage(rw http.ResponseWriter, r *http.Request) {
	users, _ := w.s.store.ListUsers(r.Context())
	w.render(rw, r, "settings_users", page{Title: "Users", Nav: "settings", Data: map[string]any{"Users": users}})
}

func (w *webUI) handleUserCreate(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	if name == "" || strings.ContainsAny(name, " \t/\\") {
		redirectError(rw, r, "/settings/users", "Invalid user name.")
		return
	}
	if err := validatePassword(pw); err != nil {
		redirectError(rw, r, "/settings/users", err.Error())
		return
	}
	hash, _ := hashPassword(pw)
	if err := w.s.store.CreateUser(r.Context(), &store.User{Username: name, PasswordHash: hash, MustChangePassword: true}); err != nil {
		redirectError(rw, r, "/settings/users", "Could not create user (name taken?)")
		return
	}
	w.s.store.Audit(r.Context(), actor(r), "user.created", name)
	redirectFlash(rw, r, "/settings/users", "User "+name+" created. They have to change the password at first login.")
}

func (w *webUI) handleUserAction(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := w.s.store.UserByID(ctx, id)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	me := userFrom(ctx)
	switch r.PathValue("action") {
	case "password":
		pw := r.PostFormValue("password")
		if err := validatePassword(pw); err != nil {
			redirectError(rw, r, "/settings/users", err.Error())
			return
		}
		hash, _ := hashPassword(pw)
		_ = w.s.store.SetPassword(ctx, u.ID, hash, u.ID != me.ID)
		_ = w.s.store.DeleteUserSessions(ctx, u.ID, sessionFrom(ctx).IDHash)
		w.s.store.Audit(ctx, actor(r), "user.password_reset", u.Username)
		redirectFlash(rw, r, "/settings/users", "Password of "+u.Username+" set.")
	case "disable", "enable":
		if u.ID == me.ID {
			redirectError(rw, r, "/settings/users", "You cannot disable yourself.")
			return
		}
		dis := r.PathValue("action") == "disable"
		_ = w.s.store.SetUserDisabled(ctx, u.ID, dis)
		if dis {
			_ = w.s.store.DeleteUserSessions(ctx, u.ID, "")
		}
		w.s.store.Audit(ctx, actor(r), "user."+r.PathValue("action"), u.Username)
		redirectFlash(rw, r, "/settings/users", "User "+u.Username+" updated.")
	case "delete":
		if u.ID == me.ID {
			redirectError(rw, r, "/settings/users", "You cannot delete yourself.")
			return
		}
		_ = w.s.store.DeleteUser(ctx, u.ID)
		w.s.store.Audit(ctx, actor(r), "user.deleted", u.Username)
		redirectFlash(rw, r, "/settings/users", "User "+u.Username+" deleted.")
	default:
		http.NotFound(rw, r)
	}
}

// ---------------------------------------------------------------------------
// settings: general
// ---------------------------------------------------------------------------

func (w *webUI) handleGeneralPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	audit, _ := w.s.store.ListAudit(ctx, 200)
	w.render(rw, r, "settings_general", page{Title: "General", Nav: "settings", Data: map[string]any{
		"General": w.s.generalSettings(ctx), "Audit": audit, "Config": w.s.cfg, "TZ": time.Local.String(), "BaseURL": w.s.baseURL(r),
	}})
}

func (w *webUI) handleGeneralSave(rw http.ResponseWriter, r *http.Request) {
	g := w.s.generalSettings(r.Context())
	if n := strings.TrimSpace(r.PostFormValue("instance_name")); n != "" {
		g.InstanceName = truncate(n, 60)
	}
	days, err := strconv.Atoi(r.PostFormValue("retention_days"))
	if err != nil || days < 7 || days > 3650 {
		redirectError(rw, r, "/settings/general", "Retention must be between 7 and 3650 days.")
		return
	}
	g.RetentionDays = days
	_ = w.s.store.PutSetting(r.Context(), setGeneral, g)
	w.s.store.Audit(r.Context(), actor(r), "general.saved", "")
	redirectFlash(rw, r, "/settings/general", "Saved.")
}
