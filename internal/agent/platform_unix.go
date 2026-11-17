//go:build !windows

package agent

// PlatformMain handles platform specific entry points (none on Unix).
func PlatformMain(args []string) (bool, int) { return false, 0 }

// InstallInteractive installs the agent (dialogs exist on Windows only).
func InstallInteractive(server, token string, quiet bool) error { return Install(server, token) }

// UninstallInteractive removes the agent.
func UninstallInteractive(quiet bool) error { return Uninstall() }

func platformAfterUpdate() {}
