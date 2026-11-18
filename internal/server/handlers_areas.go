package server

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/commifreak/inventory/internal/server/store"
)

// ---------------------------------------------------------------------------
// settings: areas
// ---------------------------------------------------------------------------

type areaMember struct {
	Username string
	Sources  []string // manual, oidc
}

type areaView struct {
	store.Area
	Devices int
	Members []areaMember
}

func (w *webUI) handleAreasPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	counts, _ := w.s.store.AreaDeviceCounts(ctx)
	ms, _ := w.s.store.Memberships(ctx, 0)
	users, _ := w.s.store.ListUsers(ctx)
	names := map[int64]string{}
	for _, u := range users {
		names[u.ID] = u.Username
	}
	var views []areaView
	for _, a := range w.s.visibleAreas(ctx) {
		v := areaView{Area: a, Devices: counts[a.ID]}
		byUser := map[int64]int{}
		for _, m := range ms {
			if m.AreaID != a.ID {
				continue
			}
			i, ok := byUser[m.UserID]
			if !ok {
				i = len(v.Members)
				byUser[m.UserID] = i
				v.Members = append(v.Members, areaMember{Username: names[m.UserID]})
			}
			v.Members[i].Sources = append(v.Members[i].Sources, m.Source)
		}
		slices.SortFunc(v.Members, func(a, b areaMember) int {
			return strings.Compare(strings.ToLower(a.Username), strings.ToLower(b.Username))
		})
		views = append(views, v)
	}
	w.render(rw, r, "settings_areas", page{Title: "Areas", Nav: "settings", Data: map[string]any{
		"Areas": views, "OIDC": w.s.cfg.OIDC.Enabled(), "GroupsClaim": w.s.cfg.OIDC.GroupsClaim, "SMTP": w.s.smtpSettings(ctx).Configured(),
	}})
}

func areaFormName(r *http.Request) (name, group string, err error) {
	name = truncate(strings.TrimSpace(r.PostFormValue("name")), 60)
	group = truncate(strings.TrimSpace(r.PostFormValue("oidc_group")), 200)
	if name == "" {
		return "", "", errors.New("Please enter a name for the area.")
	}
	return name, group, nil
}

func (w *webUI) handleAreaCreate(rw http.ResponseWriter, r *http.Request) {
	name, group, err := areaFormName(r)
	if err != nil {
		redirectError(rw, r, "/settings/areas", err.Error())
		return
	}
	a, err := w.s.store.CreateArea(r.Context(), name, group)
	if err != nil {
		redirectError(rw, r, "/settings/areas", "Could not create the area (name taken?).")
		return
	}
	w.s.auditArea(r, a.ID, "area.created", fmt.Sprintf("%s (group %q)", a.Name, group))
	redirectFlash(rw, r, "/settings/areas", "Area "+a.Name+" created. Create an enrollment token for it under Install agents.")
}

// handleAreaSave saves an area. Area admins may change the recipients of
// their areas; superadmins also name and OIDC group.
func (w *webUI) handleAreaSave(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc := accessFrom(ctx)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := w.s.store.AreaByID(ctx, id)
	if err != nil || !acc.sees(a.ID) {
		http.NotFound(rw, r)
		return
	}
	rcpt := mergeRecipients(splitList(r.PostFormValue("recipients")))
	if err := w.s.store.SetAreaRecipients(ctx, a.ID, rcpt); err != nil {
		redirectError(rw, r, "/settings/areas", err.Error())
		return
	}
	details := fmt.Sprintf("%s: recipients %s", a.Name, strings.Join(rcpt, ", "))
	if acc.Super {
		name, group, err := areaFormName(r)
		if err != nil {
			redirectError(rw, r, "/settings/areas", err.Error())
			return
		}
		if err := w.s.store.UpdateArea(ctx, a.ID, name, group); err != nil {
			redirectError(rw, r, "/settings/areas", "Could not save the area (name taken?).")
			return
		}
		details += fmt.Sprintf("; name %q, group %q", name, group)
	}
	w.s.auditArea(r, a.ID, "area.saved", details)
	redirectFlash(rw, r, "/settings/areas", "Area saved.")
}

func (w *webUI) handleAreaDelete(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a, err := w.s.store.AreaByID(ctx, id)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	if areas, _ := w.s.store.ListAreas(ctx); len(areas) <= 1 {
		redirectError(rw, r, "/settings/areas", "The last area cannot be deleted.")
		return
	}
	if err := w.s.store.DeleteArea(ctx, a.ID); err != nil {
		if errors.Is(err, store.ErrAreaNotEmpty) {
			err = errors.New("Area " + a.Name + " still has devices. Move or delete them first.")
		}
		redirectError(rw, r, "/settings/areas", err.Error())
		return
	}
	w.s.store.Audit(ctx, actor(r), "area.deleted", a.Name)
	redirectFlash(rw, r, "/settings/areas", "Area "+a.Name+" deleted.")
}

// ---------------------------------------------------------------------------
// settings: audit log
// ---------------------------------------------------------------------------

func (w *webUI) handleAuditPage(rw http.ResponseWriter, r *http.Request) {
	acc := accessFrom(r.Context())
	audit, _ := w.s.store.ListAudit(r.Context(), 300, acc.Super, acc.Areas)
	w.render(rw, r, "settings_audit", page{Title: "Audit log", Nav: "settings", Data: map[string]any{"Audit": audit}})
}

// ---------------------------------------------------------------------------
// settings: users (superadmins)
// ---------------------------------------------------------------------------

type userView struct {
	store.User
	Manual []int64  // manually assigned areas
	OIDC   []string // area names from OIDC groups
	Areas  []string // all area names
}

func (w *webUI) handleUsersPage(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, _ := w.s.store.ListUsers(ctx)
	ms, _ := w.s.store.Memberships(ctx, 0)
	areas, _ := w.s.store.ListAreas(ctx)
	names := map[int64]string{}
	for _, a := range areas {
		names[a.ID] = a.Name
	}
	var views []userView
	for _, u := range users {
		v := userView{User: u}
		for _, m := range ms {
			if m.UserID != u.ID {
				continue
			}
			if m.Source == store.MemberManual {
				v.Manual = append(v.Manual, m.AreaID)
			} else {
				v.OIDC = append(v.OIDC, names[m.AreaID])
			}
			if !slices.Contains(v.Areas, names[m.AreaID]) {
				v.Areas = append(v.Areas, names[m.AreaID])
			}
		}
		slices.Sort(v.Areas)
		views = append(views, v)
	}
	w.render(rw, r, "settings_users", page{Title: "Users", Nav: "settings", Data: map[string]any{
		"Users": views, "AllAreas": areas, "AdminGroup": w.s.cfg.OIDC.AdminGroup, "OIDC": w.s.cfg.OIDC.Enabled(),
	}})
}

func formAreaIDs(r *http.Request) []int64 {
	_ = r.ParseForm()
	var out []int64
	for _, v := range r.PostForm["area"] {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

func (w *webUI) handleUserCreate(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	super := r.PostFormValue("superadmin") == "1"
	areas := formAreaIDs(r)
	if !super && len(areas) == 0 {
		redirectError(rw, r, "/settings/users", "Choose at least one area or make the user a superadmin.")
		return
	}
	hash, _ := hashPassword(pw)
	u := &store.User{Username: name, PasswordHash: hash, MustChangePassword: true, Superadmin: super}
	if err := w.s.store.CreateUser(ctx, u); err != nil {
		redirectError(rw, r, "/settings/users", "Could not create user (name taken?)")
		return
	}
	_ = w.s.store.SetMemberships(ctx, u.ID, store.MemberManual, areas)
	w.s.store.Audit(ctx, actor(r), "user.created", fmt.Sprintf("%s (superadmin=%v, areas %v)", name, super, areas))
	redirectFlash(rw, r, "/settings/users", "User "+name+" created. They have to change the password at first login.")
}

// lastSuperadmin reports whether u is the only enabled superadmin.
func (w *webUI) lastSuperadmin(r *http.Request, u *store.User) bool {
	if !u.Superadmin || u.Disabled {
		return false
	}
	n, err := w.s.store.CountActiveSuperadmins(r.Context(), u.ID)
	return err != nil || n == 0
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
		if u.OIDCSubject != "" && u.PasswordHash == "" {
			redirectError(rw, r, "/settings/users", "This user signs in via single sign-on.")
			return
		}
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
		dis := r.PathValue("action") == "disable"
		if dis && u.ID == me.ID {
			redirectError(rw, r, "/settings/users", "You cannot disable yourself.")
			return
		}
		if dis && w.lastSuperadmin(r, u) {
			redirectError(rw, r, "/settings/users", "The last active superadmin cannot be disabled.")
			return
		}
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
		if w.lastSuperadmin(r, u) {
			redirectError(rw, r, "/settings/users", "The last active superadmin cannot be deleted.")
			return
		}
		_ = w.s.store.DeleteUser(ctx, u.ID)
		w.s.store.Audit(ctx, actor(r), "user.deleted", u.Username)
		redirectFlash(rw, r, "/settings/users", "User "+u.Username+" deleted.")
	case "superadmin":
		on := r.PostFormValue("superadmin") == "1"
		if u.OIDCSubject != "" && w.s.cfg.OIDC.AdminGroup != "" {
			redirectError(rw, r, "/settings/users", "Superadmin rights of single sign-on users come from the group "+w.s.cfg.OIDC.AdminGroup+".")
			return
		}
		if !on && u.ID == me.ID {
			redirectError(rw, r, "/settings/users", "You cannot remove your own superadmin rights.")
			return
		}
		if !on && w.lastSuperadmin(r, u) {
			redirectError(rw, r, "/settings/users", "The last active superadmin cannot lose the superadmin rights.")
			return
		}
		_ = w.s.store.SetSuperadmin(ctx, u.ID, on)
		w.s.store.Audit(ctx, actor(r), "user.superadmin", fmt.Sprintf("%s: %v", u.Username, on))
		redirectFlash(rw, r, "/settings/users", "User "+u.Username+" updated.")
	case "areas":
		areas := formAreaIDs(r)
		if err := w.s.store.SetMemberships(ctx, u.ID, store.MemberManual, areas); err != nil {
			redirectError(rw, r, "/settings/users", err.Error())
			return
		}
		w.s.store.Audit(ctx, actor(r), "user.areas", fmt.Sprintf("%s: manual areas %v", u.Username, areas))
		redirectFlash(rw, r, "/settings/users", "Areas of "+u.Username+" saved.")
	default:
		http.NotFound(rw, r)
	}
}
