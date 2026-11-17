package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/release"
)

const maxBinarySize = 200 << 20

// update downloads, verifies and installs another agent version. On success
// it returns ErrRestart: the process exits and the service manager starts
// the new binary.
func (a *Agent) update(ctx context.Context, offer *protocol.UpdateOffer) error {
	if offer.Signature == "" {
		return errors.New("refusing unsigned agent binary")
	}
	if offer.Size <= 0 || offer.Size > maxBinarySize {
		return fmt.Errorf("invalid binary size %d", offer.Size)
	}
	cur := BinaryPath()
	newPath := cur + ".new"
	_ = os.Remove(newPath)
	a.log.Info("downloading update", "version", offer.Version)
	dctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if err := a.client.Download(dctx, offer.URL, newPath, offer.Size); err != nil {
		_ = os.Remove(newPath)
		return err
	}
	if err := VerifyBinary(newPath, offer); err != nil {
		_ = os.Remove(newPath)
		return err
	}
	if err := selftest(ctx, newPath, offer.Version); err != nil {
		_ = os.Remove(newPath)
		return fmt.Errorf("self test of new binary failed: %w", err)
	}
	a.state.PendingUpdate = &PendingUpdate{From: Version, To: offer.Version, StartedAt: time.Now()}
	if err := SaveState(a.state); err != nil {
		_ = os.Remove(newPath)
		return err
	}
	if err := swapBinary(cur, newPath); err != nil {
		a.state.PendingUpdate = nil
		_ = SaveState(a.state)
		_ = os.Remove(newPath)
		return fmt.Errorf("replacing binary: %w", err)
	}
	a.log.Info("update installed, restarting", "from", Version, "to", offer.Version)
	return ErrRestart
}

// VerifyBinary checks hash, size and the publisher signature of a file.
func VerifyBinary(path string, offer *protocol.UpdateOffer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	sum, n, err := release.HashReader(f)
	f.Close()
	if err != nil {
		return err
	}
	if n != offer.Size {
		return fmt.Errorf("size mismatch: got %d, want %d", n, offer.Size)
	}
	if !strings.EqualFold(sum, offer.SHA256) {
		return errors.New("SHA-256 mismatch")
	}
	if err := release.Verify(release.TrustedKeys(), runtime.GOOS, runtime.GOARCH, offer.Version, sum, offer.Signature); err != nil {
		return fmt.Errorf("signature check failed: %w", err)
	}
	return nil
}

// selftest runs "<binary> selftest" and checks the reported version.
func selftest(ctx context.Context, path, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "selftest")
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	got := strings.TrimSpace(string(out))
	if got != want {
		return fmt.Errorf("binary reports version %q, expected %q", got, want)
	}
	return nil
}

// checkPendingUpdate runs at start-up. If an update was installed but the
// new binary keeps failing before it confirms a successful check-in, the
// previous binary is restored.
func (a *Agent) checkPendingUpdate() error {
	p := a.state.PendingUpdate
	if p == nil {
		return nil
	}
	switch Version {
	case p.To:
		p.Attempts++
		if p.Attempts > 3 && time.Since(p.StartedAt) > 10*time.Minute {
			a.log.Error("new version did not come up properly, rolling back", "version", Version, "attempts", p.Attempts)
			if err := restoreOldBinary(BinaryPath()); err != nil {
				a.log.Error("rollback failed", "err", err)
				// Keep running the new version.
				a.state.PendingUpdate = nil
				a.state.UpdateResult = &protocol.UpdateResult{FromVersion: p.From, ToVersion: p.To, Success: false, Error: "new version unstable; rollback failed: " + err.Error(), Time: time.Now()}
				return SaveState(a.state)
			}
			a.state.UpdateResult = &protocol.UpdateResult{FromVersion: p.From, ToVersion: p.To, Success: false, Error: "new version failed to check in, rolled back", Time: time.Now()}
			a.state.PendingUpdate = nil
			_ = SaveState(a.state)
			return ErrRestart
		}
		a.state.UpdateResult = &protocol.UpdateResult{FromVersion: p.From, ToVersion: p.To, Success: true, Time: time.Now()}
		return SaveState(a.state)
	case p.From:
		// Still the old binary: the swap did not take effect or was rolled back.
		if a.state.UpdateResult == nil {
			a.state.UpdateResult = &protocol.UpdateResult{FromVersion: p.From, ToVersion: p.To, Success: false, Error: "agent restarted with the previous version", Time: time.Now()}
		}
		a.state.PendingUpdate = nil
		return SaveState(a.state)
	default:
		a.state.PendingUpdate = nil
		return SaveState(a.state)
	}
}

func removeOldBinary() { _ = os.Remove(BinaryPath() + ".old") }

// swapBinary moves newPath into place, keeping the current binary as .old.
// Renaming a running executable is allowed on Windows and Unix.
func swapBinary(cur, newPath string) error {
	old := cur + ".old"
	_ = os.Remove(old)
	if err := os.Rename(cur, old); err != nil {
		return err
	}
	if err := os.Rename(newPath, cur); err != nil {
		_ = os.Rename(old, cur)
		return err
	}
	return nil
}

func restoreOldBinary(cur string) error {
	old := cur + ".old"
	if _, err := os.Stat(old); err != nil {
		return err
	}
	bad := cur + ".failed"
	_ = os.Remove(bad)
	if err := os.Rename(cur, bad); err != nil {
		return err
	}
	return os.Rename(old, cur)
}
