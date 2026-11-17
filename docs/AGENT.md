# Agent

A single static binary per platform, no runtime dependencies. It runs as a
service (Windows service / systemd / launchd) with system privileges, enrolls
itself with the token embedded in the installer and then only reports data.
It does not accept commands from the server.

## Installation

**Windows 10/11 (x64, ARM64)** – download the installer under *Settings →
Install agents* and run it. It asks for administrator rights (UAC), installs
the service and confirms with a dialog. Silent installation (e.g. via a
deployment tool):

```
inventory-agent-setup-amd64.exe /install /quiet
```

Installers are not code-signed yet: SmartScreen shows *Windows protected your
PC* → *More info* → *Run anyway*. See [SIGNING.md](SIGNING.md).

**Linux (systemd; x64, arm64, armv7/armv6)** and **macOS 13+** – run the
command shown in the UI as root:

```
curl -fsSL 'https://inventory.example.com/api/agent/v1/install/<token>/install.sh' | sudo sh
```

On Linux the script installs `smartmontools` with the system package manager
if missing. On macOS install it with `brew install smartmontools` for disk data.

Reinstalling on the same machine keeps the device (matched by SMBIOS UUID and
machine id) and its history.

## Files

| | Windows | Linux | macOS |
|---|---|---|---|
| Binary | `C:\Program Files\Inventory Agent\inventory-agent.exe` | `/usr/local/lib/inventory-agent/inventory-agent` | `/Library/Application Support/Inventory Agent/inventory-agent` |
| Config/state | `C:\ProgramData\Inventory Agent\` (SYSTEM + Administrators only, credential DPAPI-protected) | `/var/lib/inventory-agent/` (root, 0700) | `.../Inventory Agent/data/` |
| Log | `C:\ProgramData\Inventory Agent\agent.log` | `journalctl -u inventory-agent` | `.../data/agent.log` |
| Service | `InventoryAgent` | `inventory-agent.service` | `io.github.commifreak.inventory-agent` |

## Command line

```
inventory-agent status            # enrollment, last check-in, last collector runs
inventory-agent collect [name…]   # run collectors and print the JSON (diagnostics)
inventory-agent run               # foreground (debug: INVENTORY_DEBUG=1)
inventory-agent uninstall [--quiet]
inventory-agent version
```

Collector names: `system`, `smart`, `updates`, `software`, `autostart`, `events`.

## Uninstall

Windows: *Settings → Apps → Inventory Agent → Uninstall* or
`"C:\Program Files\Inventory Agent\inventory-agent.exe" uninstall --quiet`.
Linux/macOS: `sudo inventory-agent uninstall`. This removes the service,
binary and local data. Delete the device in the web UI afterwards.

## What the agent does not do

- No remote commands, scripts or file transfer.
- No changes to the system: update searches only read; on Linux package lists
  are not refreshed (the timestamp of the last refresh is reported instead).
- No collection of user files, browser data or license keys.

## Self-updates

At check-in the server may offer another version (see *Settings → Agent
updates*). The agent downloads it, verifies SHA-256 and the publisher's Ed25519
signature (the public key is compiled into the agent), runs a self test of the
new binary, swaps the binaries and restarts through the service manager. If the
new version does not come up and check in, the previous binary is restored.

## Troubleshooting

- *Device does not appear*: check `inventory-agent status` and the log. The
  client needs outbound HTTPS to the server URL (no inbound ports).
- *No SMART data on Windows*: RAID controllers and some USB enclosures hide
  disks; the agent falls back to the Windows storage API (less detail).
- *Raspberry Pi / SD cards*: SD cards have no SMART. They are listed in the
  Disks tab; read/write errors are detected from the kernel log (journal and
  `dmesg`) and raise the "Disk errors in system log" alert.
- *Wi-Fi name missing on Windows 11 24H2+*: Windows only reveals the SSID with
  location services enabled.
- *Update searches fail*: shown as "check failing" with the Windows Update
  error code; an alert fires after the configured number of days.
