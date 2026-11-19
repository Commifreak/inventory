package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/release"
)

// changelog writes the changelog bundled with the server: per release tag
// (and the unreleased commits of an edge build) the subjects of the commits
// on main – squash-merged pull requests – that change more than docs,
// tests, CI or scripts.
//
//	inventory-release changelog -version 0.3.1-edge.202611191200 -out internal/server/changelog.json [-repo owner/name] [-max 10]
func changelog(args []string) error {
	fs := flag.NewFlagSet("changelog", flag.ExitOnError)
	version := fs.String("version", "", "version of this build (used for unreleased changes)")
	out := fs.String("out", "internal/server/changelog.json", "output file")
	repo := fs.String("repo", os.Getenv("GITHUB_REPOSITORY"), "owner/name for links to pull requests")
	maxReleases := fs.Int("max", 10, "number of releases to include")
	_ = fs.Parse(args)

	tags, err := stableTags()
	if err != nil {
		return err
	}
	cl := release.Changelog{Repo: *repo}
	head, _ := git("rev-parse", "HEAD")
	if len(tags) > 0 {
		last := tags[len(tags)-1]
		lastCommit, _ := git("rev-list", "-n1", "v"+last)
		if strings.TrimSpace(head) != strings.TrimSpace(lastCommit) && *version != "" {
			r, err := releaseFor(*version, "v"+last, "HEAD")
			if err != nil {
				return err
			}
			if len(r.Entries) > 0 {
				cl.Releases = append(cl.Releases, r)
			}
		}
	}
	for i := len(tags) - 1; i >= 0 && len(cl.Releases) < *maxReleases; i-- {
		prev := ""
		if i > 0 {
			prev = "v" + tags[i-1]
		}
		r, err := releaseFor(tags[i], prev, "v"+tags[i])
		if err != nil {
			return err
		}
		cl.Releases = append(cl.Releases, r)
	}
	b, err := json.MarshalIndent(cl, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("changelog: %d release(s)\n", len(cl.Releases))
	return os.WriteFile(*out, append(b, '\n'), 0o644)
}

var prSuffix = regexp.MustCompile(`\s*\(#(\d+)\)$`)

// releaseFor collects the user-facing commits in from..to (from == "": the
// first release, listed as a single entry).
func releaseFor(version, from, to string) (release.ChangelogRelease, error) {
	date, err := git("log", "-1", "--format=%cI", to)
	if err != nil {
		return release.ChangelogRelease{}, err
	}
	r := release.ChangelogRelease{Version: version, Date: parseTime(date)}
	if from == "" {
		r.Entries = []release.ChangelogEntry{{Title: "First release", Date: r.Date}}
		return r, nil
	}
	log, err := git("log", "--first-parent", "--format=%H%x1f%cI%x1f%s", from+".."+to)
	if err != nil {
		return r, err
	}
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		f := strings.SplitN(line, "\x1f", 3)
		if len(f) != 3 {
			continue
		}
		files, err := git("diff-tree", "--no-commit-id", "--name-only", "-r", f[0])
		if err != nil || !userFacing(strings.Fields(files)) {
			continue
		}
		e := release.ChangelogEntry{Title: f[2], Date: parseTime(f[1])}
		if m := prSuffix.FindStringSubmatch(e.Title); m != nil {
			e.PR, _ = strconv.Atoi(m[1])
			e.Title = strings.TrimSpace(prSuffix.ReplaceAllString(e.Title, ""))
		}
		r.Entries = append(r.Entries, e)
	}
	return r, nil
}

// userFacing reports whether a commit changes more than documentation,
// tests, CI configuration or build scripts.
func userFacing(files []string) bool {
	for _, f := range files {
		if strings.HasPrefix(f, "docs/") || strings.HasPrefix(f, ".github/") || strings.HasPrefix(f, "scripts/") ||
			strings.HasSuffix(f, ".md") || strings.HasSuffix(f, "_test.go") {
			continue
		}
		return true
	}
	return false
}

func stableTags() ([]string, error) {
	out, err := git("tag", "--list", "v*")
	if err != nil {
		return nil, err
	}
	var tags []string
	for _, t := range strings.Fields(out) {
		if regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(t) {
			tags = append(tags, strings.TrimPrefix(t, "v"))
		}
	}
	sortVersions(tags)
	return tags, nil
}

// sortVersions sorts X.Y.Z versions ascending.
func sortVersions(v []string) {
	key := func(s string) [3]int {
		var k [3]int
		for i, p := range strings.SplitN(s, ".", 3) {
			k[i], _ = strconv.Atoi(p)
		}
		return k
	}
	for i := 1; i < len(v); i++ {
		for j := i; j > 0; j-- {
			a, b := key(v[j-1]), key(v[j])
			if a[0] > b[0] || a[0] == b[0] && (a[1] > b[1] || a[1] == b[1] && a[2] > b[2]) {
				v[j-1], v[j] = v[j], v[j-1]
			}
		}
	}
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(s))
	return t.UTC()
}

func git(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}
