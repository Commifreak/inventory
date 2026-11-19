package release

import "time"

// Changelog is the list of user-facing changes bundled with the server
// (generated at build time from the squash-merged pull requests).
type Changelog struct {
	Repo     string             `json:"repo,omitempty"` // owner/name, for links to pull requests
	Releases []ChangelogRelease `json:"releases"`       // newest first
}

// ChangelogRelease is a release (or the unreleased changes of an edge build).
type ChangelogRelease struct {
	Version string           `json:"version"`
	Date    time.Time        `json:"date"`
	Entries []ChangelogEntry `json:"entries"`
}

// ChangelogEntry is one change: the title of a pull request.
type ChangelogEntry struct {
	Title string    `json:"title"`
	PR    int       `json:"pr,omitempty"`
	Date  time.Time `json:"date"`
}
