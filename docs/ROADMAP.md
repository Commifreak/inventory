# Roadmap

| # | Milestone | State |
|---|---|---|
| 1 | Server core: database, local login, web UI, agent API, Docker image | done |
| 2 | Windows agent: installer, service, SMART, Windows Update, software, extras | done – collectors verified on a Windows CI runner; installer/service need a test on a real client |
| 3 | Alerts via SMTP with configurable rules | done |
| 4 | Agent self-updates: signing, rings, pause, pin, update now, rollback | done |
| 5 | Linux agent (x64, arm64, armv7) with install script | done |
| 6 | OIDC login (Authentik, Authelia) | done – needs testing against the IdPs |
| 7 | macOS agent | basic implementation, untested |

## Next steps

- Field test on Windows 10/11 clients (x64 and ARM64) and Linux distributions;
  fix collector edge cases.
- Authenticode signing of Windows installers (tag stored in the certificate
  table), see [SIGNING.md](SIGNING.md).
- Read the Windows event log via the native API instead of `wevtutil`.
- `.deb`/`.rpm` packages for manual installation.
- Additional notification channels (ntfy, Gotify, webhooks).
- macOS: notarised builds, field test.
- Public key rotation helper.

## Ideas (not planned)

- Microsoft Store (Appx) app inventory
- winget based "outdated software" report
- Per-device alert rule overrides beyond the offline threshold
- Remote support: not built into the agent (read-only principle, attack surface);
  possible later: show the RustDesk/MeshCentral ID of a client with a connect link
- RAID controller details via vendor tools (storcli etc.)
