package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/commifreak/inventory/internal/release"
	"github.com/commifreak/inventory/internal/server/store"
)

// AgentRepo holds the agent binaries known to this server. Binaries shipped
// with the image (AGENTS_DIR) are copied into DATA_DIR/agents on start so
// older versions stay available for pinning and rollback.
type AgentRepo struct {
	dir      string
	mu       sync.RWMutex
	versions map[string]*release.Manifest
}

func newAgentRepo(bundledDir, dataDir string, log *slog.Logger) (*AgentRepo, error) {
	r := &AgentRepo{dir: filepath.Join(dataDir, "agents"), versions: map[string]*release.Manifest{}}
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		return nil, err
	}
	if bundledDir != "" {
		if err := r.importDir(bundledDir, log); err != nil {
			log.Warn("importing bundled agents failed", "dir", bundledDir, "err", err)
		}
	}
	return r, r.Reload()
}

// importDir copies <bundledDir>/<version>/ into the repository if missing.
// A version already present is replaced when its manifest differs (e.g. an
// "edge" build with the same version string), so that it is always consistent.
func (r *AgentRepo) importDir(bundledDir string, log *slog.Logger) error {
	entries, err := os.ReadDir(bundledDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		src := filepath.Join(bundledDir, e.Name())
		mb, err := os.ReadFile(filepath.Join(src, "manifest.json"))
		if err != nil {
			continue
		}
		var m release.Manifest
		if err := json.Unmarshal(mb, &m); err != nil || m.Version == "" || !safeName(m.Version) {
			log.Warn("invalid bundled manifest", "dir", src)
			continue
		}
		dst := filepath.Join(r.dir, m.Version)
		if old, err := os.ReadFile(filepath.Join(dst, "manifest.json")); err == nil && string(old) == string(mb) {
			continue
		}
		tmp := dst + ".tmp"
		_ = os.RemoveAll(tmp)
		if err := os.MkdirAll(tmp, 0o755); err != nil {
			return err
		}
		for _, b := range m.Binaries {
			if !safeName(b.File) {
				return fmt.Errorf("bad file name %q", b.File)
			}
			if err := copyFile(filepath.Join(src, b.File), filepath.Join(tmp, b.File)); err != nil {
				return err
			}
		}
		if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), mb, 0o644); err != nil {
			return err
		}
		_ = os.RemoveAll(dst)
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		log.Info("imported agent version", "version", m.Version)
	}
	return nil
}

func safeName(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Reload rescans the repository.
func (r *AgentRepo) Reload() error {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return err
	}
	versions := map[string]*release.Manifest{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasSuffix(e.Name(), ".tmp") {
			continue
		}
		mb, err := os.ReadFile(filepath.Join(r.dir, e.Name(), "manifest.json"))
		if err != nil {
			continue
		}
		var m release.Manifest
		if json.Unmarshal(mb, &m) == nil && m.Version == e.Name() {
			versions[m.Version] = &m
		}
	}
	r.mu.Lock()
	r.versions = versions
	r.mu.Unlock()
	return nil
}

// Prune removes old versions: the newest keepNewest versions and all
// versions for which inUse returns true are kept.
func (r *AgentRepo) Prune(keepNewest int, inUse func(string) bool, log *slog.Logger) {
	for i, m := range r.Versions() {
		if i < keepNewest || inUse(m.Version) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(r.dir, m.Version)); err == nil {
			log.Info("removed old agent version", "version", m.Version)
		}
	}
	_ = r.Reload()
}

// Versions returns all versions, newest first.
func (r *AgentRepo) Versions() []*release.Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*release.Manifest, 0, len(r.versions))
	for _, m := range r.versions {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return CompareVersions(out[i].Version, out[j].Version) > 0 })
	return out
}

// Binary returns the binary of a version for a platform.
func (r *AgentRepo) Binary(version, goos, goarch string) (*release.Binary, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.versions[version]
	if !ok {
		return nil, "", false
	}
	for i := range m.Binaries {
		b := &m.Binaries[i]
		if b.OS == goos && b.Arch == goarch {
			return b, filepath.Join(r.dir, version, b.File), true
		}
	}
	return nil, "", false
}

// Latest returns the newest version available for a platform. If
// signedOnly is set, unsigned builds are skipped (agents refuse them).
func (r *AgentRepo) Latest(goos, goarch string, signedOnly bool) string {
	for _, m := range r.Versions() {
		if b, _, ok := r.Binary(m.Version, goos, goarch); ok && (!signedOnly || b.Signature != "") {
			return m.Version
		}
	}
	return ""
}

// LatestAny returns the newest version overall.
func (r *AgentRepo) LatestAny() string {
	v := r.Versions()
	if len(v) == 0 {
		return ""
	}
	return v[0].Version
}

// CompareVersions compares semantic versions like "1.2.3", "1.2.3-edge.20261117".
// Pre-releases sort before the release. Unparseable versions sort first.
func CompareVersions(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	if a == b {
		return 0
	}
	ac, ap, _ := strings.Cut(strings.SplitN(a, "+", 2)[0], "-")
	bc, bp, _ := strings.Cut(strings.SplitN(b, "+", 2)[0], "-")
	// Versions without a numeric core (e.g. "dev") sort before everything else.
	av, bv := numericCore(ac), numericCore(bc)
	switch {
	case !av && !bv:
		return strings.Compare(a, b)
	case !av:
		return -1
	case !bv:
		return 1
	}
	if c := compareDotted(ac, bc); c != 0 {
		return c
	}
	switch {
	case ap == "" && bp == "":
		return strings.Compare(a, b)
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	return compareDotted(ap, bp)
}

func numericCore(s string) bool {
	for _, p := range strings.Split(s, ".") {
		if _, err := strconv.ParseUint(p, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func compareDotted(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		an, aerr := strconv.ParseUint(as[i], 10, 64)
		bn, berr := strconv.ParseUint(bs[i], 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return 0
}

// Update states stored on the device.
const (
	updOffered = "offered"
	updFailed  = "failed"
	updDone    = "done"
)

// TargetVersion decides which agent version a device should run.
// It returns "" when the device should stay on its current version.
func TargetVersion(d *store.Device, p UpdatePolicy, repo *AgentRepo) (target, reason string) {
	available := func(v string) bool {
		b, _, ok := repo.Binary(v, d.OS, d.Arch)
		return ok && b.Signature != ""
	}
	latest := repo.Latest(d.OS, d.Arch, true)
	switch {
	case d.Managed == "home-assistant":
		return "", "updated by Home Assistant (add-on updates)"
	case d.Managed != "":
		return "", "updated by " + d.Managed
	case d.PinnedVersion != "":
		if available(d.PinnedVersion) {
			return d.PinnedVersion, "pinned"
		}
		return "", "pinned version not available"
	case d.UpdateNowVersion != "":
		if available(d.UpdateNowVersion) {
			return d.UpdateNowVersion, "manual update"
		}
		return "", "requested version not available"
	case p.Paused:
		return "", "updates paused"
	}
	v := p.RingVersions[d.Ring]
	if v == "" {
		if latest == "" {
			return "", "no signed agent available"
		}
		return latest, "ring " + d.Ring + " follows latest"
	}
	if !available(v) {
		return "", "ring version not available"
	}
	// A ring version never downgrades a device that was updated manually.
	if d.AgentVersion != "" && CompareVersions(d.AgentVersion, v) > 0 {
		return "", "device is newer than ring " + d.Ring
	}
	return v, "ring " + d.Ring
}
