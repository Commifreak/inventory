package server

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"time"

	"github.com/commifreak/inventory/internal/release"
)

// changelog.json is generated at build time (inventory-release changelog);
// the committed file is empty.
//
//go:embed changelog.json
var changelogJSON []byte

func loadChangelog() release.Changelog {
	var cl release.Changelog
	_ = json.Unmarshal(changelogJSON, &cl)
	return cl
}

// unseenChanges returns the releases with changes newer than the user last
// dismissed. Users who never dismissed see the changes of the newest
// release (since the previous one).
func unseenChanges(cl release.Changelog, seen time.Time) []release.ChangelogRelease {
	if len(cl.Releases) == 0 {
		return nil
	}
	if seen.IsZero() {
		if len(cl.Releases) > 1 {
			seen = cl.Releases[1].Date
		} else {
			seen = time.Unix(1, 0)
		}
	}
	var out []release.ChangelogRelease
	for _, r := range cl.Releases {
		var entries []release.ChangelogEntry
		for _, e := range r.Entries {
			if e.Date.After(seen) {
				entries = append(entries, e)
			}
		}
		if len(entries) > 0 {
			r.Entries = entries
			out = append(out, r)
		}
	}
	return out
}

func (w *webUI) handleChangelogPage(rw http.ResponseWriter, r *http.Request) {
	w.render(rw, r, "changelog", page{Title: "What's new", Data: map[string]any{"Changelog": w.s.changelog}})
}

// handleChangelogSeen dismisses the "What's new" notice of the user.
func (w *webUI) handleChangelogSeen(rw http.ResponseWriter, r *http.Request) {
	if impersonatorFrom(r.Context()) == nil {
		_ = w.s.store.SetChangelogSeen(r.Context(), userFrom(r.Context()).ID, time.Now())
	}
	http.Redirect(rw, r, safeNext(r.PostFormValue("next")), http.StatusSeeOther)
}
