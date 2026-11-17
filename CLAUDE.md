# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Working rules

- Talk to the maintainer in **German**; everything in the repository (code, comments,
  UI texts, mails, docs, commit messages) is **English**.
- Clarify open questions before starting larger changes; small, obvious fixes can be done directly.
- Pushing directly to `main` is allowed.
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
| `internal/server` | HTTP handlers, ingest, alert rules (`alerts.go` catalog), update targeting (`agents.go`), end-of-support data (`eol.go`), OIDC, web UI (`web/templates`, `web/static`) |
| `internal/server/store` | SQLite access; schema changes only via new files in `migrations/` (next: `0004_*.sql`) |
| `internal/agent` | agent loop, self-update, collectors per OS (`*_windows.go`, `*_linux.go`, `*_darwin.go`), installers; shared parsers: `smbios.go` (memory/slots), `sysprofiler.go` (macOS), `proxy.go` (system proxy), `diag.go` (agent diagnostics) |
| `internal/release` | Ed25519 signing; trusted public key in `keys/official.pub` |
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
- Rejected enrollments/installer downloads (unknown/revoked token) are logged to the server
  log and audit log with only a token prefix.
- Tests must not depend on the host (e.g. `pci.ids`, `/etc/environment`) and must not write
  outside temp dirs: Linux paths are relocatable via `testRoot`/`sys` parameters, the
  diagnostics log via `diagLog.path`.
- UI: strict CSP – no inline scripts or `style=` attributes; JS lives in `web/static/app.js`.

## Releases

- Push to `main` → `ghcr.io/commifreak/inventory:edge`, agent version `<VERSION>-edge.<timestamp>`.
- Tag `vX.Y.Z` → `:X.Y.Z`, `:X.Y`, `:latest`; bump `VERSION` afterwards.

## Verification status

Verified: tests/CI, several real Windows 11 clients (HP ProBook, Lenovo ThinkPad T480, …;
data reviewed via raw exports, incl. memory modules, M.2 slots, NVMe controller, agent
self-update). Not yet verified on real systems: Linux install via systemd, SMTP delivery,
OIDC with Authentik/Authelia, macOS, Raspberry Pi features (SD card errors, undervoltage),
proxy via Windows user settings/PAC/WPAD, SATA controllers on Windows.
