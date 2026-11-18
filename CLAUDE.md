# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Working rules

- Talk to the maintainer in **German**; everything in the repository (code, comments,
  UI texts, mails, docs, commit messages) is **English**.
- Clarify open questions before starting larger changes; small, obvious fixes can be done directly.
- Pushing directly to `main` is allowed (also in `Commifreak/inventory-ha-addon`). Both
  repositories are public: never commit personal data (domains, names, IPs of clients).
- The product is **read-only monitoring**: agents report data, the server never executes
  anything on clients. Do not add remote actions without an explicit decision.
- Decisions are documented in `docs/SPEC.md`, status and ideas in `docs/ROADMAP.md` – keep both current.

## Commands

```bash
go test ./...                                  # unit + end-to-end tests (server e2e, agent lifecycle)
go vet ./...
for p in windows/amd64 windows/arm64 linux/arm64 darwin/arm64; do \
  GOOS=${p%/*} GOARCH=${p#*/} go vet ./internal/agent/ ./cmd/inventory-agent/; done
gofmt -l .                                     # CI fails on unformatted code
go run ./cmd/inventory-agent collect [name]    # run collectors of this machine, prints JSON
go run ./cmd/inventory-agent proxy [URL]       # proxy the agent would use and its source
SMARTCTL_SKIP=1 ./scripts/build-agents.sh      # build all 7 agent platforms (unsigned)
DATA_DIR=./data AGENTS_DIR=./dist/agents INITIAL_ADMIN_PASSWORD=dev-password-123 \
  LISTEN_ADDR=127.0.0.1:8080 go run ./cmd/inventory-server
```

Windows code cannot run here (Linux container): compile/vet it with `GOOS=windows`; the CI
job on `windows-latest` (a Hyper-V VM) runs the real collectors (`inventory-agent collect`,
prints memory modules, slots and storage controllers) and checks the WinHTTP proxy path.
Read its log after pushing Windows changes.

UI changes: render pages in a throwaway test (`newTestServer` + `sampleReport`, inline
`app.css`) and screenshot them with Playwright before pushing.

## Layout

| Path | |
|---|---|
| `cmd/inventory-server`, `cmd/inventory-agent`, `cmd/inventory-release` | entry points (server, agent CLI/installer, manifest + signing tool) |
| `internal/protocol` | wire format shared by agent and server (`data.go` = collector payloads) |
| `internal/server` | HTTP handlers, ingest, alert rules (`alerts.go` catalog), update targeting (`agents.go`), end-of-support data (`eol.go`), OIDC, areas/access (`access.go`, `handlers_areas.go`), web UI (`web/templates`, `web/static`) |
| `internal/server/store` | SQLite access; schema changes only via new files in `migrations/` (next: `0007_*.sql`) |
| `internal/agent` | agent loop, self-update, collectors per OS (`*_windows.go`, `*_linux.go`, `*_darwin.go`), installers; shared parsers: `smbios.go` (memory/slots), `sysprofiler.go` (macOS), `proxy.go` (system proxy), `diag.go` (agent diagnostics) |
| `internal/release` | Ed25519 signing; trusted public key in `keys/official.pub` |
| `ha-addon/Dockerfile` | image of the Home Assistant add-on (definition in the separate repo `Commifreak/inventory-ha-addon`); add-on mode of the agent: `internal/agent/addon_linux.go` |
| `internal/tag` | install tag (server URL + enrollment token) appended to Windows installers |

## Conventions and pitfalls

- New collector fields: add to `internal/protocol/data.go` (use `omitzero` for `time.Time`),
  fill them in every OS collector where possible, render in `device.html`, extend
  `internal/server/server_test.go` sample data. Old agents send the field absent – the UI
  must handle nil/zero values.
- New alert rules: add to `RuleCatalog` in `internal/server/alerts.go` and evaluate in
  `evaluateDevice`; rules that could not be evaluated must not resolve open alerts.
- Windows COM (go-ole): `forEach` releases each collection item itself – callbacks must not
  call `Release()` (double release crashes the process). Run COM in a goroutine with
  `runtime.LockOSThread()` and recover panics.
- Windows data must be language independent (German systems!): use IDs/SIDs/GUIDs
  (e.g. update classification IDs, `S-1-5-32-544`), not display names.
- The Windows agent is built with `-H windowsgui`; `attachParentConsole` makes CLI output visible.
- The server distributes only agent versions bundled in its image (`AGENTS_DIR`, copied to
  `DATA_DIR/agents`); agents update only after the image is re-pulled.
- Agents refuse unsigned updates. CI signs with the GitHub secret `RELEASE_SIGNING_KEY`
  passed via `secret-envs` (the `secrets` input of build-push-action breaks multi-line PEM).
- After an agent version change all collectors run once immediately (`resetOnVersionChange`).
- Hardware quirks are handled by data, not names: Windows storage controller types come from
  the PCI class code (`CC_0106…`), vendors from the PCI vendor ID; M.2 slots are also
  recognised by designation (HP reports them as PCIe slot types).
- End-of-support data comes only from endoflife.date (cached in `DATA_DIR/eol`, no built-in
  table); the UI warns when fetching fails for 3 days. OS and Office rules use it.
- The agent uses the system proxy (env → Windows WinHTTP → user WinINet incl. PAC/WPAD;
  Linux `/etc/environment`; macOS `scutil`). Warnings/errors of the agent are kept in
  `diag.json` and sent with every check-in (shown on the Agent tab).
- Change alerts (new admin/autostart/Defender exclusion) compare against everything ever seen
  per device (`seen_items`, first report = baseline) and are stored as events; evaluate them
  in the event-rule loop. Rules can be disabled per device (`devices.disabled_rules`).
- Rejected enrollments/installer downloads (unknown/revoked token) are logged to the server
  log and audit log with only a token prefix.
- Tests must not depend on the host (e.g. `pci.ids`, `/etc/environment`) and must not write
  outside temp dirs: Linux paths are relocatable via `testRoot`/`sys` parameters, the
  diagnostics log via `diagLog.path`.
- UI: strict CSP – no inline scripts or `style=` attributes; JS lives in `web/static/app.js`.
- Areas: every device/token belongs to an area. New UI handlers must check access:
  devices via `loadDevice` (404 for other areas), lists via `visibleDevices`/`accessFrom(ctx).sees`,
  global settings via `requireSuper`. Audit device/token actions with `auditArea`.
  `TestAreaIsolation` must cover new routes. Re-enrollment matches only within the
  token's area (`FindDeviceByIdentity(areaID, …)`).
- OIDC: `OIDC_ISSUER` is used as given (Authentik's issuer ends with `/`; the other spelling
  is tried on a mismatch). Groups/name/e-mail fall back to the userinfo endpoint
  (Authelia 4.39+ puts only minimal claims into the ID token).
- Home Assistant add-on mode (`inventory-agent addon`): the container hides host mounts,
  `/sys/firmware` and `/etc/machine-id`; use the Supervisor API with the default role
  (only `…/info` endpoints – `/addons` returns 403, installed add-ons come from
  `/supervisor/info`, host DNS/DHCP/Wi-Fi from `/network/info`). Add-on agents report
  `managed: home-assistant` and never self-update.

## Releases

- Push to `main` → `ghcr.io/commifreak/inventory:edge`, agent version from `scripts/version.sh`:
  newest tag with patch+1 plus `-edge.<timestamp>` (e.g. `0.2.1-edge…` after `v0.2.0`), so edge
  sorts above the last release and below every following one. No version file to bump.
- Tag `vX.Y.Z` → `:X.Y.Z`, `:X.Y`, `:latest`. Tags also build
  `ghcr.io/commifreak/inventory-ha-agent:X.Y.Z` and set the version in the add-on repo
  (secret `ADDON_REPO_TOKEN`); the CI builds the add-on image (without push) on every push.
  The Home Assistant add-on only follows these stable releases.
- Claude sessions cannot push tags (git proxy rejects them with 403): the maintainer creates
  releases in the GitHub UI (tag `vX.Y.Z` on `main`). Released: `v0.1.1`.

## Verification status

Verified: tests/CI, several real Windows 11 clients (HP ProBook, Lenovo ThinkPad T480, CSL
desktop with AMD/ASUS board; data reviewed via raw exports, incl. memory modules, M.2 slots,
NVMe controller, agent self-update), OIDC login with Authelia, Home Assistant add-on on a
Raspberry Pi 4 (HAOS 18.5, add-on 0.1.1).
Not yet verified on real systems: Linux install via systemd, SMTP delivery, OIDC with
Authentik, macOS, Raspberry Pi undervoltage/SD card error detection with real faults,
proxy via Windows user settings/PAC/WPAD, SATA controllers on Windows, Defender detections
on a real client, areas with real OIDC groups (Authelia/Authentik).
