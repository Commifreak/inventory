# Third-party notices

## smartmontools (smartctl.exe)

Windows agent binaries embed `smartctl.exe` from smartmontools 7.5, unmodified,
extracted from the official Windows installer
(`smartmontools-7.5.win32-setup.exe`, SHA-256
`896337fcc253220614cf8cdbd5cf2321c5aa326a37a04160a672a281e6104c70`).
At runtime it is written to `C:\ProgramData\Inventory Agent\bin\smartctl.exe`
and executed as a separate program.

- License: GNU General Public License version 2 or later
- Copyright (C) 2002-2025 Bruce Allen, Christian Franke and contributors
- Website and source code: https://www.smartmontools.org/ ,
  https://sourceforge.net/projects/smartmontools/files/smartmontools/7.5/

## Go modules

| Module | License |
|---|---|
| modernc.org/sqlite (and modernc.org/* dependencies) | BSD-3-Clause |
| golang.org/x/sys, golang.org/x/crypto, golang.org/x/oauth2 | BSD-3-Clause |
| github.com/coreos/go-oidc/v3 | Apache-2.0 |
| github.com/go-jose/go-jose/v4 | Apache-2.0 |
| github.com/go-ole/go-ole | MIT |
| github.com/yusufpapurcu/wmi | MIT |

The full list including versions is in `go.mod`/`go.sum`.
