package server

import (
	"context"
	"net/http"
	"slices"

	"github.com/commifreak/inventory/internal/server/store"
)

// access describes what the signed-in user may see. Superadmins see every
// area and may change global settings; other users see the devices, tokens,
// alerts and audit entries of their areas only.
type access struct {
	Super bool
	Areas []int64 // areas the user is a member of
}

// sees reports whether the user may see objects of an area.
func (a *access) sees(areaID int64) bool {
	return a != nil && (a.Super || slices.Contains(a.Areas, areaID))
}

func accessFrom(ctx context.Context) *access {
	a, _ := ctx.Value(ctxAccess).(*access)
	return a
}

// loadAccess resolves the access of a user.
func (s *Server) loadAccess(ctx context.Context, u *store.User) (*access, error) {
	areas, err := s.store.UserAreaIDs(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return &access{Super: u.Superadmin, Areas: areas}, nil
}

// errNoArea is shown to users who are neither superadmin nor member of an area.
const errNoArea = "Your account is not assigned to any area. Please ask an administrator."

// requireSuper protects routes that only superadmins may use (global settings, users, areas).
func (s *Server) requireSuper(next http.HandlerFunc) http.HandlerFunc {
	return s.requireUser(func(w http.ResponseWriter, r *http.Request) {
		if !accessFrom(r.Context()).Super {
			http.Error(w, "only superadmins may do this", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// visibleAreas returns the areas the user may see, sorted by name.
func (s *Server) visibleAreas(ctx context.Context) []store.Area {
	acc := accessFrom(ctx)
	all, _ := s.store.ListAreas(ctx)
	var out []store.Area
	for _, a := range all {
		if acc.sees(a.ID) {
			out = append(out, a)
		}
	}
	return out
}

// visibleDevices returns the devices the user may see.
func (s *Server) visibleDevices(ctx context.Context) ([]store.Device, error) {
	devices, err := s.store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	acc := accessFrom(ctx)
	return slices.DeleteFunc(devices, func(d store.Device) bool { return !acc.sees(d.AreaID) }), nil
}

// auditArea records an audit entry for an area with the acting user.
func (s *Server) auditArea(r *http.Request, areaID int64, action, details string) {
	s.store.AuditArea(r.Context(), areaID, actor(r), action, details)
}

// duplicateIdentities maps device IDs to devices of other areas with the same
// hardware (a machine re-enrolled with a token of another area). Shown to
// superadmins, who can move the device and delete the stale entry.
func duplicateIdentities(devices []store.Device) map[string][]store.Device {
	out := map[string][]store.Device{}
	for i, a := range devices {
		for j, b := range devices {
			if i == j || a.AreaID == b.AreaID || (a.HardwareID == "" && a.MachineID == "") {
				continue
			}
			if store.SameIdentity(a.HardwareID, a.MachineID, b.HardwareID, b.MachineID) {
				out[a.ID] = append(out[a.ID], b)
			}
		}
	}
	return out
}
