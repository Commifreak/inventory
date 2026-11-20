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

**Linux (systemd; x64, arm64, armv7/armv6)** and **macOS 12+** (Monterey; the Go toolchain does not support older versions – the installer refuses them) – run the
command shown in the UI as root:

```
curl -fsSL 'https://inventory.example.com/api/agent/v1/install/<token>/install.sh' | sudo sh
```

On Linux the script installs `smartmontools` with the system package manager
if missing. On macOS install it with `brew install smartmontools` for disk data.

Reinstalling on the same machine keeps the device (matched by SMBIOS UUID and
machine id) and its history.

## Home Assistant OS

Home Assistant OS has a read-only system without package manager, so the agent
runs there as the **Home Assistant add-on "Inventory Agent"**
([add-on repository](https://github.com/Commifreak/inventory-ha-addon)):

1. *Settings → Install agents* → section *Home Assistant OS*: button to add the
   add-on repository to Home Assistant, plus server URL and token to copy.
2. Install the add-on, enter `server_url` and `enrollment_token` in its
   configuration, enable *Start on boot* and *Watchdog*, start it.

The add-on runs `inventory-agent addon`: configuration from the add-on options,
data in the add-on's `/data` (survives restarts and OS updates), no self-update
(new versions arrive as add-on updates for releases `vX.Y.Z`; the server shows the
device as "Home Assistant add-on" and never offers it updates). OS, Home Assistant
and add-on versions and their available updates come from the Supervisor API;
hardware, network, SMART (full hardware access) and Raspberry Pi power data from the
host; kernel messages from the host journal. If the device is deleted on the
server, the add-on enrolls again with the token from its options.

## Files

| | Windows | Linux | macOS |
|---|---|---|---|
| Binary | `C:\Program Files\Inventory Agent\inventory-agent.exe` | `/usr/local/lib/inventory-agent/inventory-agent` | `/Library/Application Support/Inventory Agent/inventory-agent` |
| Config/state | `C:\ProgramData\Inventory Agent\` (SYSTEM + Administrators only, credential DPAPI-protected) | `/var/lib/inventory-agent/` (root, 0700) | `.../Inventory Agent/data/` |
| Log | `C:\ProgramData\Inventory Agent\agent.log` | `journalctl -u inventory-agent` | `.../data/agent.log` |
| Diagnostics | `diag.json` in the config/state directory: the latest 20 warnings/errors, sent with every check-in | | |
| Service | `InventoryAgent` | `inventory-agent.service` | `io.github.commifreak.inventory-agent` |

## Command line

```
inventory-agent status            # enrollment, proxy, last check-in, last collector runs
inventory-agent proxy [URL]       # proxy used for URL (default: the server URL) and its source
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

## Proxy

The agent uses the system proxy for all connections (check-in, reports,
updates). Sources, first match wins:

1. `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` in the service environment.
2. Platform settings:
   - **Windows:** the machine-wide WinHTTP proxy (`netsh winhttp set proxy`),
     otherwise the proxy settings (*Settings → Network & internet → Proxy*) of
     the user of the active session – or the machine-wide settings when the
     policy `ProxySettingsPerUser=0` is set – including a PAC script and
     automatic detection (WPAD). While nobody is signed in, the settings of the
     last signed-in user are kept.
   - **Linux:** `http(s)_proxy` / `no_proxy` in `/etc/environment` (systemd does
     not pass it to services).
   - **macOS:** the HTTP/HTTPS proxy and exceptions of the network settings
     (`scutil --proxy`). PAC scripts and auto discovery are not evaluated.

Settings are re-read every two minutes, no restart needed. Proxy
authentication is limited to Basic credentials in the proxy URL
(`http://user:password@proxy:3128`); NTLM/Kerberos proxies are not supported.
The proxy in use is logged on changes and shown by `inventory-agent status` and
`inventory-agent proxy [URL]`.
The Linux/macOS install script uses the same sources for its downloads.

## Self-updates

At check-in the server may offer another version (see *Settings → Agent
updates*). The agent downloads it, verifies SHA-256 and the publisher's Ed25519
signature (the public key is compiled into the agent), runs a self test of the
new binary, swaps the binaries and restarts through the service manager. If the
new version does not come up and check in, the previous binary is restored.

## Troubleshooting

- *Agent problems*: the *Agent* tab shows "Agent diagnostics" – the proxy in use
  and the latest warnings/errors of the agent (last 30 days, also those logged
  while the server was unreachable; sent with the next check-in). The raw data
  export contains them too.
- *Device does not appear*: check `inventory-agent status` and the log. The
  client needs outbound HTTPS to the server URL (no inbound ports), directly or
  through the system proxy (see *Proxy*).
- *No SMART data on Windows*: RAID controllers and some USB enclosures hide
  disks; the agent falls back to the Windows storage API (less detail).
- *Raspberry Pi / SD cards*: SD cards have no SMART. They are listed in the
  Disks tab; read/write errors are detected from the kernel log (journal and
  `dmesg`) and raise the "Disk errors in system log" alert. Undervoltage (the
  most common cause of corrupted SD cards) is recorded as an event, the
  firmware throttling state is shown on the Overview tab, and the
  "Undervoltage (Raspberry Pi)" alert fires.
- *Wi-Fi name missing on Windows 11 24H2+*: Windows only reveals the SSID with
  location services enabled.
- *Update searches fail*: shown as "check failing" with the Windows Update
  error code; an alert fires after the configured number of days.
