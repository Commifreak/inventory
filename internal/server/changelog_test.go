package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/release"
)

func TestWhatsNew(t *testing.T) {
	s, ts, _ := newTestServer(t)
	ctx := context.Background()
	now := time.Now()
	s.changelog = release.Changelog{Repo: "Commifreak/inventory", Releases: []release.ChangelogRelease{
		{Version: "0.4.0", Date: now.Add(-time.Hour), Entries: []release.ChangelogEntry{
			{Title: "Show <new> things", PR: 12, Date: now.Add(-2 * time.Hour)}, {Title: "Fix a bug", PR: 11, Date: now.Add(-3 * time.Hour)}}},
		{Version: "0.3.0", Date: now.Add(-48 * time.Hour), Entries: []release.ChangelogEntry{{Title: "Old change", PR: 5, Date: now.Add(-50 * time.Hour)}}},
	}}
	// Existing user (never dismissed): the changes of the newest release.
	admin, _ := s.store.UserByName(ctx, "admin")
	_ = s.store.SetPassword(ctx, admin.ID, admin.PasswordHash, false)
	_, _ = s.store.DB.Exec(`UPDATE users SET changelog_seen_at=NULL WHERE id=?`, admin.ID)
	adm, p := login(t, ts, "admin", "initial-password-1")
	if !strings.Contains(p, "What's new in Inventory") || !strings.Contains(p, "Show &lt;new&gt; things") || !strings.Contains(p, "pull/12") || strings.Contains(p, "Old change") || !strings.Contains(p, "2 changes") {
		i := strings.Index(p, "whatsnew")
		if i < 0 {
			i = 0
		}
		t.Fatalf("notice missing or wrong: %s", p[i:min(len(p), i+1500)])
	}
	// Dismissed: gone; the changelog page lists everything.
	adm.post("/changelog/seen", url.Values{"next": {"/"}})
	if _, p := adm.get("/"); strings.Contains(p, "What's new in Inventory") {
		t.Fatal("notice still shown after dismissing")
	}
	if _, p := adm.get("/changelog"); !strings.Contains(p, "Old change") || !strings.Contains(p, "Fix a bug") {
		t.Fatal("changelog page incomplete")
	}
	// New users start with everything seen.
	addUser(t, s, "dora", true)
	if _, p := login(t, ts, "dora", "area-password-123"); strings.Contains(p, "What's new in Inventory") {
		t.Fatal("notice shown to a new user")
	}
	// A later change appears for those who dismissed before.
	s.changelog.Releases[0].Entries = append([]release.ChangelogEntry{{Title: "Brand new", PR: 13, Date: time.Now().Add(time.Minute)}}, s.changelog.Releases[0].Entries...)
	if _, p := adm.get("/"); !strings.Contains(p, "Brand new") || strings.Contains(p, "Fix a bug") {
		t.Fatal("only the new change should be listed")
	}
}
