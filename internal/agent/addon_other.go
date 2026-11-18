//go:build !linux

package agent

import (
	"context"
	"errors"
	"log/slog"
)

// The Home Assistant add-on mode exists on Linux only.

// RunAddon is not available on this platform.
func RunAddon(context.Context, *slog.Logger) error {
	return errors.New("the Home Assistant add-on mode is only available on Linux")
}

func managedBy() string { return "" }

func (a *Agent) reEnrollFromOptions() bool { return false }
