# Inventory

Self-hosted inventory and health monitoring for a handful (or a few hundred) of
Windows, Linux and macOS clients – disk health (SMART), update status, software
inventory and e-mail alerts, in one Docker container.

- **One-click agent install** – the server generates the installer with its own
  address and an enrollment token embedded. No configuration on the client.
- **Zero-touch** – agents get all settings from the server and update themselves
  (signed updates, rollout rings, pause, manual update, automatic rollback).
- **Read-only monitoring** – agents only report; the server cannot run commands on clients.

| Area | What is collected |
|---|---|
| Disks | SMART for all disks (system disk highlighted): health, temperature, reallocated/pending/uncorrectable sectors, NVMe wear and spare, trends |
| Updates | Windows Update (pending, history incl. failures with error codes, reboot pending, WSUS, services) · apt/dnf/zypper/pacman · macOS softwareupdate |
| Software | Installed software with change log (installed / updated / removed) |
| System | OS and build, end of support, hardware, volumes, network (IPs, gateway, DNS, Wi-Fi), last logons and administrators |
| Security | Defender (incl. passive mode), Secure Boot and the 2023 UEFI CA certificates, TPM, activation, BitLocker / LUKS / FileVault, battery health |
| Autostart | Run keys, startup folders, scheduled tasks, services · systemd, cron @reboot, XDG · launchd |
| Events | Bluescreens / kernel panics, disk and SD card errors, out-of-memory kills, Raspberry Pi undervoltage |

Alerts (SMTP) are rule based and configurable in the UI: SMART failures and
thresholds, low disk space, failed or long pending updates, pending reboots,
end of support, Defender off, missing Secure Boot certificates, bluescreens,
disk errors, devices offline and more.

## Quick start

```yaml
# docker-compose.yml – see docker-compose.example.yml for Traefik labels
services:
  inventory:
    image: ghcr.io/commifreak/inventory:latest
    restart: unless-stopped
    environment:
      BASE_URL: https://inventory.example.com
      TZ: Europe/Berlin
    volumes:
      - inventory-data:/data
volumes:
  inventory-data:
```

1. `docker compose up -d`, then read the initial `admin` password from the log:
   `docker compose logs inventory` (or set `INITIAL_ADMIN_PASSWORD`).
2. Sign in and change the password.
3. **Settings → E-mail**: configure SMTP; **Settings → Alert rules**: add recipients.
4. **Settings → Install agents**: download the Windows installer or copy the
   Linux/macOS command and run it on a client.

The image `ghcr.io/commifreak/inventory` is pulled without credentials once its
GHCR package is public. For a private package (e.g. in a fork), run
`docker login ghcr.io` with a personal access token (`read:packages`), or give
Portainer the registry credentials.

## Documentation

- [Configuration](docs/CONFIGURATION.md) – environment variables, reverse proxy, single sign-on
- [Agent](docs/AGENT.md) – installation, data collected, files, CLI, troubleshooting
- [Signing](docs/SIGNING.md) – update signing key, SmartScreen, code signing options
- [Specification](docs/SPEC.md) and [Roadmap](docs/ROADMAP.md)
- [Development](docs/DEVELOPMENT.md)

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Windows agents embed `smartctl.exe` from
[smartmontools](https://www.smartmontools.org/) (GPL-2.0), see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
