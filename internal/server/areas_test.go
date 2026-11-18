package server

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/server/store"
)

// webClient is a signed-in browser session.
type webClient struct {
	t    *testing.T
	c    *http.Client
	base string
	csrf string
}

func login(t *testing.T, ts *httptest.Server, user, pw string) (*webClient, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.PostForm(ts.URL+"/login", url.Values{"username": {user}, "password": {pw}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	wc := &webClient{t: t, c: c, base: ts.URL}
	if m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(string(b)); m != nil {
		wc.csrf = m[1]
	}
	return wc, string(b)
}

func (w *webClient) get(path string) (int, string) {
	w.t.Helper()
	resp, err := w.c.Get(w.base + path)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (w *webClient) post(path string, v url.Values) (int, string) {
	w.t.Helper()
	if v == nil {
		v = url.Values{}
	}
	v.Set("csrf", w.csrf)
	resp, err := w.c.PostForm(w.base+path, v)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func addUser(t *testing.T, s *Server, name string, super bool, areas ...int64) *store.User {
	t.Helper()
	ctx := context.Background()
	hash, _ := hashPassword("area-password-123")
	u := &store.User{Username: name, PasswordHash: hash, Superadmin: super}
	if err := s.store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetMemberships(ctx, u.ID, store.MemberManual, areas); err != nil {
		t.Fatal(err)
	}
	return u
}

func enroll(t *testing.T, ts *httptest.Server, token string, id protocol.Identity) protocol.EnrollResponse {
	t.Helper()
	var er protocol.EnrollResponse
	if code := postJSON(t, ts.URL+protocol.APIPrefix+"/enroll", "", protocol.EnrollRequest{Token: token, Identity: id, AgentVersion: "0.0.9"}, &er); code != 200 {
		t.Fatalf("enroll %s: %d", id.Hostname, code)
	}
	return er
}

// TestAreaIsolation checks that a user of area B reaches nothing of area A,
// also not via direct URLs.
func TestAreaIsolation(t *testing.T) {
	s, ts, fm := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	tokA := toks[0]
	areaB, err := s.store.CreateArea(ctx, "Workshop", "inventory-workshop")
	if err != nil {
		t.Fatal(err)
	}
	tokB, _ := s.store.CreateToken(ctx, randomToken(24), "Workshop token", areaB.ID)

	now := time.Now()
	devA := enroll(t, ts, tokA.Token, protocol.Identity{Hostname: "PC-ALPHA", OS: "windows", Arch: "amd64", HardwareID: "HW-A", MachineID: "M-A"})
	devB := enroll(t, ts, tokB.Token, protocol.Identity{Hostname: "PC-BRAVO", OS: "windows", Arch: "amd64", HardwareID: "HW-B", MachineID: "M-B"})
	for _, cred := range []string{devA.Credential, devB.Credential} {
		if code := postJSON(t, ts.URL+protocol.APIPrefix+"/report", cred, sampleReport(now), nil); code != 200 {
			t.Fatalf("report: %d", code)
		}
	}

	// The same hardware enrolled with the token of area B becomes a new
	// device; the device of area A keeps its identity and credential.
	dup := enroll(t, ts, tokB.Token, protocol.Identity{Hostname: "PC-ALPHA", OS: "windows", Arch: "amd64", HardwareID: "HW-A", MachineID: "M-A"})
	if dup.DeviceID == devA.DeviceID {
		t.Fatal("device of area A was taken over by area B")
	}
	if code := postJSON(t, ts.URL+protocol.APIPrefix+"/checkin", devA.Credential, protocol.CheckinRequest{AgentVersion: "0.0.9"}, nil); code != 200 {
		t.Fatalf("credential of the area A device invalidated: %d", code)
	}
	if d, _ := s.store.DeviceByID(ctx, dup.DeviceID); d == nil || d.AreaID != areaB.ID {
		t.Fatalf("duplicate not in area B: %+v", d)
	}
	// Re-enrolling within the same area still recognises the device.
	if again := enroll(t, ts, tokB.Token, protocol.Identity{Hostname: "PC-ALPHA", OS: "windows", Arch: "amd64", HardwareID: "HW-A", MachineID: "M-A"}); again.DeviceID != dup.DeviceID {
		t.Fatal("re-enrollment within the area created another device")
	}

	// Alert mails go to the global recipients and additionally to the area's.
	_ = s.store.PutSetting(ctx, setSMTP, SMTPSettings{Host: "localhost", From: "inv@example.com", Port: 25})
	as := s.alertSettings(ctx)
	as.Recipients = []string{"admin@example.com"}
	_ = s.store.PutSetting(ctx, setAlerts, as)
	_ = s.store.SetAreaRecipients(ctx, areaB.ID, []string{"workshop@example.com", "Admin@example.com"})
	s.runAlerts(ctx, nil)
	var toA, toB string
	for i, subj := range fm.sent {
		switch {
		case strings.Contains(subj, "PC-ALPHA"):
			// both PC-ALPHA devices: area A (global only) and area B (with area recipients)
			if strings.Join(fm.to[i], ",") == "admin@example.com" {
				toA = strings.Join(fm.to[i], ",")
			}
		case strings.Contains(subj, "PC-BRAVO"):
			toB = strings.Join(fm.to[i], ",")
		}
	}
	if toA != "admin@example.com" || toB != "admin@example.com,workshop@example.com" {
		t.Errorf("recipients: area A %q, area B %q (mails %v %v)", toA, toB, fm.sent, fm.to)
	}

	addUser(t, s, "bob", false, areaB.ID)
	addUser(t, s, "carol", false)
	admin, _ := s.store.UserByName(ctx, "admin")
	_ = s.store.SetPassword(ctx, admin.ID, admin.PasswordHash, false)

	// A user without area cannot sign in.
	if _, page := login(t, ts, "carol", "area-password-123"); !strings.Contains(page, "not assigned to any area") {
		t.Errorf("user without area signed in")
	}

	bob, page := login(t, ts, "bob", "area-password-123")
	if !strings.Contains(page, "PC-BRAVO") || strings.Contains(page, devA.DeviceID) {
		t.Fatalf("bob's dashboard is wrong")
	}
	// Device pages, raw export and actions of area A do not exist for bob.
	for _, p := range []string{"/devices/" + devA.DeviceID, "/devices/" + devA.DeviceID + "?tab=agent", "/devices/" + devA.DeviceID + "/raw.json",
		"/downloads/windows/" + strconv.FormatInt(tokA.ID, 10) + "/amd64"} {
		if code, _ := bob.get(p); code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, code)
		}
	}
	for _, p := range []string{"/settings", "/rules", "/update-now", "/collect", "/revoke", "/delete", "/area"} {
		if code, _ := bob.post("/devices/"+devA.DeviceID+p, url.Values{"display_name": {"hacked"}, "area_id": {strconv.FormatInt(areaB.ID, 10)}}); code != http.StatusNotFound && code != http.StatusForbidden {
			t.Errorf("POST %s: %d", p, code)
		}
	}
	if d, err := s.store.DeviceByID(ctx, devA.DeviceID); err != nil || d.DisplayName != "" || !d.RevokedAt.IsZero() || d.CollectNow != "" || d.AreaID != 1 {
		t.Fatalf("device of area A was changed by bob: %+v %v", d, err)
	}
	bob.post("/devices/bulk", url.Values{"ids": {devA.DeviceID, devB.DeviceID}, "action": {"collect"}})
	if a, _ := s.store.DeviceByID(ctx, devA.DeviceID); a.CollectNow != "" {
		t.Error("bulk action applied to a device of area A")
	}
	if b, _ := s.store.DeviceByID(ctx, devB.DeviceID); b.CollectNow == "" {
		t.Error("bulk action not applied to bob's device")
	}
	// Own device works.
	if code, p := bob.get("/devices/" + devB.DeviceID + "?tab=agent"); code != 200 || strings.Contains(p, `action="/devices/`+devB.DeviceID+`/area"`) {
		t.Errorf("own device page: %d (area admins must not get the move form)", code)
	}

	// Alerts, tokens and audit entries of area A are invisible.
	if _, p := bob.get("/alerts"); strings.Contains(p, devA.DeviceID) || !strings.Contains(p, devB.DeviceID) {
		t.Error("alerts page shows the wrong devices")
	}
	if _, p := bob.get("/settings/install"); strings.Contains(p, tokA.Token) || !strings.Contains(p, tokB.Token) {
		t.Error("install page shows the wrong tokens")
	}
	if code, _ := bob.post("/settings/tokens/"+strconv.FormatInt(tokA.ID, 10)+"/revoke", nil); code != http.StatusNotFound {
		t.Errorf("revoking a token of area A: %d", code)
	}
	if tk, _ := s.store.TokenByID(ctx, tokA.ID); !tk.Active() {
		t.Fatal("bob revoked a token of area A")
	}
	bob.post("/settings/tokens", url.Values{"name": {"sneaky"}, "area_id": {"1"}})
	bob.post("/settings/tokens", url.Values{"name": {"mine"}})
	for _, tk := range mustTokens(t, s) {
		if tk.Name == "sneaky" {
			t.Error("bob created a token in area A")
		}
		if tk.Name == "mine" && tk.AreaID != areaB.ID {
			t.Errorf("bob's token is in area %d", tk.AreaID)
		}
	}
	if _, p := bob.get("/settings/audit"); strings.Contains(p, devA.DeviceID) || !strings.Contains(p, devB.DeviceID) || strings.Contains(p, "enrollment.rejected") {
		t.Error("audit log shows entries of other areas")
	}

	// Global settings are for superadmins only.
	for _, p := range []string{"/settings/updates", "/settings/collection", "/settings/alerts", "/settings/smtp", "/settings/users", "/settings/general"} {
		if code, _ := bob.get(p); code != http.StatusForbidden {
			t.Errorf("GET %s: %d, want 403", p, code)
		}
	}
	for _, p := range []string{"/settings/general", "/settings/areas", "/settings/users", "/settings/areas/1/delete"} {
		if code, _ := bob.post(p, url.Values{"name": {"x"}, "instance_name": {"x"}, "retention_days": {"30"}, "username": {"eve"}, "password": {"eve-password-123"}, "superadmin": {"1"}}); code != http.StatusForbidden {
			t.Errorf("POST %s: %d, want 403", p, code)
		}
	}
	// Area admins edit only the recipients of their own area.
	if code, _ := bob.post("/settings/areas/1", url.Values{"recipients": {"bob@example.com"}}); code != http.StatusNotFound {
		t.Errorf("saving area A: %d", code)
	}
	bob.post("/settings/areas/"+strconv.FormatInt(areaB.ID, 10), url.Values{"recipients": {"bob@example.com"}, "name": {"Renamed"}, "oidc_group": {"admins"}})
	if a, _ := s.store.AreaByID(ctx, areaB.ID); a.Name != "Workshop" || a.OIDCGroup != "inventory-workshop" || strings.Join(a.Recipients, ",") != "bob@example.com" {
		t.Errorf("area after bob's save: %+v", a)
	}
	if _, p := bob.get("/settings/areas"); strings.Contains(p, "Default") {
		t.Error("areas page lists area A")
	}

	// Superadmin: everything, area column and the duplicate hint.
	adm, _ := login(t, ts, "admin", "initial-password-1")
	_, p := adm.get("/")
	if !strings.Contains(p, "PC-BRAVO") || !strings.Contains(p, devA.DeviceID) || !strings.Contains(p, "also in Workshop") || !strings.Contains(p, "All areas") {
		t.Errorf("superadmin dashboard incomplete")
	}
	if _, p := adm.get("/?area=" + strconv.FormatInt(areaB.ID, 10)); strings.Contains(p, devA.DeviceID+`"`) && !strings.Contains(p, "also in") {
		t.Errorf("area filter not applied")
	}
	if _, p := adm.get("/devices/" + devA.DeviceID); !strings.Contains(p, "also enrolled in another area") {
		t.Errorf("duplicate hint missing on the device page")
	}
	for _, path := range []string{"/settings/areas", "/settings/users", "/settings/audit", "/settings/install", "/settings/general"} {
		if code, _ := adm.get(path); code != 200 {
			t.Errorf("superadmin GET %s: %d", path, code)
		}
	}
	// A new area starts with an enrollment token.
	adm.post("/settings/areas", url.Values{"name": {"Family"}})
	found := false
	for _, tk := range mustTokens(t, s) {
		if tk.Name == "Family" && tk.Active() && tk.AreaID != 1 && tk.AreaID != areaB.ID {
			found = true
		}
	}
	if !found {
		t.Error("new area has no enrollment token")
	}
	// Moving a device makes it visible to bob.
	adm.post("/devices/"+devA.DeviceID+"/area", url.Values{"area_id": {strconv.FormatInt(areaB.ID, 10)}})
	if code, _ := bob.get("/devices/" + devA.DeviceID); code != 200 {
		t.Errorf("moved device not visible to bob: %d", code)
	}
	// An area with devices cannot be deleted; the last superadmin is protected.
	adm.post("/settings/areas/"+strconv.FormatInt(areaB.ID, 10)+"/delete", nil)
	if _, err := s.store.AreaByID(ctx, areaB.ID); err != nil {
		t.Error("area with devices deleted")
	}
	adm.post("/settings/users/"+strconv.FormatInt(admin.ID, 10)+"/superadmin", url.Values{"superadmin": {"0"}})
	if u, _ := s.store.UserByID(ctx, admin.ID); !u.Superadmin {
		t.Error("the last superadmin lost the rights")
	}

	// Rights are read per request: removing bob's area locks him out at once.
	bobUser, _ := s.store.UserByName(ctx, "bob")
	_ = s.store.SetMemberships(ctx, bobUser.ID, store.MemberManual, nil)
	if code, p := bob.get("/"); code != 200 || !strings.Contains(p, "not assigned to any area") {
		t.Errorf("bob still has access after losing his area: %d", code)
	}
}

func mustTokens(t *testing.T, s *Server) []store.EnrollmentToken {
	toks, err := s.store.ListTokens(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return toks
}

func TestOIDCAccountSync(t *testing.T) {
	s, _, _ := newTestServer(t)
	ctx := context.Background()
	s.cfg.OIDC.AdminGroup = "inventory-admins"
	area, _ := s.store.CreateArea(ctx, "Family", "inventory-family")
	claims := map[string]any{"preferred_username": "dave", "email": "dave@example.com"}

	// Unknown user without a granting group: rejected, not created.
	if _, err := s.oidcAccount(ctx, "sub-dave", claims, []string{"other"}); err == nil || !strings.Contains(err.Error(), "not a member of a group") {
		t.Fatalf("expected rejection, got %v", err)
	}
	if _, err := s.store.UserBySubject(ctx, "sub-dave"); err == nil {
		t.Fatal("user created without group")
	}
	// Area group: created as area user.
	u, err := s.oidcAccount(ctx, "sub-dave", claims, []string{"inventory-family"})
	if err != nil || u.Superadmin {
		t.Fatalf("login with area group: %+v %v", u, err)
	}
	if ids, _ := s.store.UserAreaIDs(ctx, u.ID); len(ids) != 1 || ids[0] != area.ID {
		t.Fatalf("areas %v", ids)
	}
	// Admin group: superadmin; losing the area group removes the area.
	u, _ = s.oidcAccount(ctx, "sub-dave", claims, []string{"inventory-admins"})
	if !u.Superadmin {
		t.Fatal("admin group did not grant superadmin")
	}
	if ids, _ := s.store.UserAreaIDs(ctx, u.ID); len(ids) != 0 {
		t.Fatalf("group area not removed: %v", ids)
	}
	// Manual areas are kept; without any group the user keeps access via them.
	_ = s.store.SetMemberships(ctx, u.ID, store.MemberManual, []int64{1})
	u, err = s.oidcAccount(ctx, "sub-dave", claims, nil)
	if err != nil || u.Superadmin {
		t.Fatalf("login with manual area only: %+v %v", u, err)
	}
	if ids, _ := s.store.UserAreaIDs(ctx, u.ID); len(ids) != 1 || ids[0] != 1 {
		t.Fatalf("manual area lost: %v", ids)
	}
	// Neither group nor manual area: rejected.
	_ = s.store.SetMemberships(ctx, u.ID, store.MemberManual, nil)
	if _, err := s.oidcAccount(ctx, "sub-dave", claims, nil); err == nil || !strings.Contains(err.Error(), "not assigned to any area") {
		t.Fatalf("expected no-area rejection, got %v", err)
	}
}

func TestImpersonation(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	toks, _ := s.store.ListTokens(ctx)
	tokA := toks[0]
	areaB, _ := s.store.CreateArea(ctx, "Workshop", "")
	tokB, _ := s.store.CreateToken(ctx, randomToken(24), "Workshop token", areaB.ID)
	devA := enroll(t, ts, tokA.Token, protocol.Identity{Hostname: "PC-ALPHA", OS: "windows", Arch: "amd64", HardwareID: "HW-A"})
	devB := enroll(t, ts, tokB.Token, protocol.Identity{Hostname: "PC-BRAVO", OS: "windows", Arch: "amd64", HardwareID: "HW-B"})
	bob := addUser(t, s, "bob", false, areaB.ID)
	carol := addUser(t, s, "carol", true)
	admin, _ := s.store.UserByName(ctx, "admin")
	_ = s.store.SetPassword(ctx, admin.ID, admin.PasswordHash, false)

	adm, _ := login(t, ts, "admin", "initial-password-1")
	// Token page: own areas in full, other areas only as a list without token values.
	_, p := adm.get("/settings/install")
	if !strings.Contains(p, tokA.Token) || strings.Contains(p, tokB.Token) || !strings.Contains(p, "Tokens of other areas") || !strings.Contains(p, "Workshop token") {
		t.Errorf("superadmin token page does not split own and other tokens")
	}

	// Area users cannot impersonate; superadmins cannot be impersonated.
	bc, _ := login(t, ts, "bob", "area-password-123")
	if code, _ := bc.post("/settings/users/"+strconv.FormatInt(carol.ID, 10)+"/impersonate", nil); code != http.StatusForbidden {
		t.Errorf("area user impersonating: %d", code)
	}
	adm.post("/settings/users/"+strconv.FormatInt(carol.ID, 10)+"/impersonate", nil)
	if code, p := adm.get("/settings/users"); code != 200 || strings.Contains(p, "Support session") {
		t.Fatalf("superadmin was impersonated: %d", code)
	}
	// A pending password change of bob has no effect in a support session,
	// and the support session is not recorded as bob's login.
	_ = s.store.SetPassword(ctx, bob.ID, bob.PasswordHash, true)
	bobBefore, _ := s.store.UserByID(ctx, bob.ID)

	// Sign in as bob: exactly bob's view and rights, banner, audited actions.
	adm.post("/settings/users/"+strconv.FormatInt(bob.ID, 10)+"/impersonate", nil)
	code, p := adm.get("/")
	if code != 200 || !strings.Contains(p, "Support session") || !strings.Contains(p, devB.DeviceID) || strings.Contains(p, devA.DeviceID) || strings.Contains(p, "Change password") {
		t.Fatalf("support session view wrong: %d", code)
	}
	if m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(p); m != nil {
		adm.csrf = m[1]
	}
	if code, _ := adm.get("/settings/users"); code != http.StatusForbidden {
		t.Errorf("superadmin pages reachable in a support session: %d", code)
	}
	if code, _ := adm.get("/devices/" + devA.DeviceID); code != http.StatusNotFound {
		t.Errorf("device of another area reachable in a support session: %d", code)
	}
	adm.post("/devices/"+devB.DeviceID+"/settings", url.Values{"display_name": {"Bravo"}, "ring": {"stable"}})
	adm.post("/account/password", url.Values{"current": {"area-password-123"}, "new": {"changed-password-1"}, "confirm": {"changed-password-1"}})
	if u, _ := s.store.UserByID(ctx, bob.ID); !checkPassword(u.PasswordHash, "area-password-123") {
		t.Error("password changed in a support session")
	}
	auditB, _ := s.store.ListAudit(ctx, 50, false, []int64{areaB.ID})
	var actions []string
	for _, a := range auditB {
		actions = append(actions, a.Username+":"+a.Action)
	}
	joined := strings.Join(actions, " ")
	if !strings.Contains(joined, "admin (as bob):device.settings") || !strings.Contains(joined, "admin:impersonation.started") {
		t.Errorf("support session not audited in the area: %v", actions)
	}

	// Back to admin.
	adm.post("/impersonate/stop", nil)
	if code, p := adm.get("/settings/users"); code != 200 || strings.Contains(p, "Support session") {
		t.Fatalf("not back as superadmin: %d", code)
	}
	global, _ := s.store.ListAudit(ctx, 50, true, nil)
	found := false
	for _, a := range global {
		if a.Action == "impersonation.ended" && a.Username == "admin (as bob)" {
			found = true
		}
	}
	if !found {
		t.Error("end of the support session not audited")
	}
	if u, _ := s.store.UserByID(ctx, bob.ID); !u.LastLoginAt.Equal(bobBefore.LastLoginAt) {
		t.Error("support session recorded as bob's login")
	}
}
