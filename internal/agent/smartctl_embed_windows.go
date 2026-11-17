//go:build windows && smartctl_embed

package agent

import _ "embed"

// smartctl.exe from smartmontools (GPL-2.0), placed here by scripts/build-agents.sh.
//
//go:embed assets/smartctl.exe
var smartctlBin []byte

func init() { embeddedSmartctl = smartctlBin }
