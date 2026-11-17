package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// runCmd runs a command and returns trimmed stdout. stderr is included in the error.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg != "" {
			return stdout.String(), fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return stdout.String(), fmt.Errorf("%s: %w", name, err)
	}
	return stdout.String(), nil
}

// exitCode returns the exit code of an error from runCmd, or -1.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func boolPtr(b bool) *bool { return &b }

// cleanID rejects placeholder hardware UUIDs and serials.
func cleanID(s string) string {
	s = strings.TrimSpace(s)
	l := strings.ToLower(s)
	switch {
	case l == "", l == "none", l == "default string", l == "to be filled by o.e.m.", l == "system serial number",
		l == "not specified", l == "0", l == "n/a", l == "not applicable", l == "chassis serial number":
		return ""
	case strings.Trim(l, "0-") == "", strings.Trim(l, "f-") == "":
		return ""
	case l == "03000200-0400-0500-0006-000700080009":
		return ""
	}
	return s
}

// uniqueStrings removes duplicates and empty strings, keeping order.
func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// applySecureBootCerts searches UEFI signature databases for the 2023
// certificates. Certificate subjects are stored as plain ASCII in the DER data.
func applySecureBootCerts(info *protocol.SecureBootInfo, db, kek []byte) {
	if len(db) > 0 {
		info.DBHasWindowsUEFICA2023 = boolPtr(bytes.Contains(db, []byte("Windows UEFI CA 2023")))
		info.DBHasMicrosoftUEFICA2023 = boolPtr(bytes.Contains(db, []byte("Microsoft UEFI CA 2023")))
		info.DBHasOptionROMCA2023 = boolPtr(bytes.Contains(db, []byte("Microsoft Option ROM UEFI CA 2023")))
	}
	if len(kek) > 0 {
		info.KEKHas2023 = boolPtr(bytes.Contains(kek, []byte("KEK 2K CA 2023")))
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
