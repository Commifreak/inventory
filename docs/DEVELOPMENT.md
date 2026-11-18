# Development

Requirements: Go (see `go.mod`), optionally Docker, `7z` and `curl` for the
Windows smartctl embedding.

```bash
go test ./...                                   # unit and end-to-end tests
go run ./cmd/inventory-server                   # needs DATA_DIR, e.g.:
DATA_DIR=./data AGENTS_DIR=./dist/agents INITIAL_ADMIN_PASSWORD=dev-password-123 \
  LISTEN_ADDR=127.0.0.1:8080 go run ./cmd/inventory-server
go run ./cmd/inventory-agent collect            # run the collectors of this machine
```

Build all agents (unsigned unless a key is given):

```bash
./scripts/build-agents.sh                                   # -> dist/agents/<last tag, patch+1>-dev
go run ./cmd/inventory-release keygen -out dev              # throwaway key pair
RELEASE_SIGNING_KEY_FILE=dev.key ./scripts/build-agents.sh
go run ./cmd/inventory-release verify -dir dist/agents/0.1.0-dev -pub dev.pub
```

Image: `docker buildx build -t inventory:dev .` (add
`--secret id=release_signing_key,src=dev.key` for signed agents).

## Layout

| Path | |
|---|---|
| `cmd/inventory-server` | server entry point |
| `cmd/inventory-agent` | agent entry point (CLI, Windows double-click installer) |
| `cmd/inventory-release` | manifest/signing tool used by the build |
| `internal/protocol` | wire format shared by agent and server |
| `internal/server` | HTTP handlers, ingest, alerts, updates, web UI (`web/`) |
| `internal/server/store` | SQLite persistence and migrations |
| `internal/agent` | agent loop, collectors per OS (`*_windows.go`, `*_linux.go`, `*_darwin.go`), installers, self-update |
| `internal/release` | Ed25519 signing, embedded public keys |
| `internal/tag` | install tag embedded into Windows installers |

## Releases

- Every push to `main` builds `ghcr.io/commifreak/inventory:edge` with agent
  version `<last tag, patch+1>-edge.<timestamp>` (`scripts/version.sh`), e.g.
  `0.2.1-edge.202611181200` after `v0.2.0`: above the last release, below every
  following one, so agents update correctly when a server switches between
  `:edge` and `:latest`.
- A tag `vX.Y.Z` builds `:X.Y.Z`, `:X.Y` and `:latest`. Nothing has to be changed afterwards.
- The workflow fails if the secret `RELEASE_SIGNING_KEY` is missing.
