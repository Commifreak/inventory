//go:build !windows

package agent

import "os/exec"

// protect is a no-op on Unix: the data directory is readable by root only.
func protect(s string) (string, error) { return s, nil }

func unprotect(s string) (string, error) { return s, nil }

func hideWindow(*exec.Cmd) {}
