#!/usr/bin/env bash
# Builds all agent binaries into dist/agents/<version> and writes the signed
# manifest. Used by the Dockerfile and CI; works locally as well.
#
# Environment:
#   VERSION                   agent version (default: contents of VERSION + "-dev")
#   RELEASE_SIGNING_KEY_FILE  path to the Ed25519 private key (PEM), optional
#   RELEASE_SIGNING_KEY       the key itself (PEM), optional
#   EXTRA_TRUSTED_KEY         base64 public key compiled into agents (forks)
#   SMARTCTL_SKIP=1           do not embed smartctl.exe into Windows agents
#   TARGETS                   space separated list, default: all platforms
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(cat VERSION)-dev}"
OUT="dist/agents/${VERSION}"
TARGETS="${TARGETS:-windows/amd64 windows/arm64 linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64}"

# smartmontools for Windows (GPL-2.0). Pinned version and checksum.
SMART_VERSION="7.5"
SMART_URL="https://downloads.sourceforge.net/project/smartmontools/smartmontools/${SMART_VERSION}/smartmontools-${SMART_VERSION}.win32-setup.exe"
SMART_SHA256="896337fcc253220614cf8cdbd5cf2321c5aa326a37a04160a672a281e6104c70"
SMART_DIR="dist/smartmontools-${SMART_VERSION}"

rm -rf "$OUT"
mkdir -p "$OUT"

fetch_smartctl() {
  [ "${SMARTCTL_SKIP:-0}" = "1" ] && return 1
  if [ ! -f "$SMART_DIR/bin/smartctl.exe" ]; then
    mkdir -p "$SMART_DIR"
    echo "fetching smartmontools ${SMART_VERSION} ..."
    curl -fsSL --retry 3 -o "$SMART_DIR/setup.exe" "$SMART_URL"
    echo "${SMART_SHA256}  $SMART_DIR/setup.exe" | sha256sum -c - >/dev/null
    (cd "$SMART_DIR" && 7z x -y setup.exe bin/smartctl.exe bin32/smartctl.exe >/dev/null)
  fi
  [ -f "$SMART_DIR/bin/smartctl.exe" ]
}

LDFLAGS="-s -w -X github.com/commifreak/inventory/internal/agent.Version=${VERSION}"
if [ -n "${EXTRA_TRUSTED_KEY:-}" ]; then
  LDFLAGS="$LDFLAGS -X github.com/commifreak/inventory/internal/release.ExtraTrustedKey=${EXTRA_TRUSTED_KEY}"
fi

HAVE_SMARTCTL=0
if fetch_smartctl; then HAVE_SMARTCTL=1; else echo "warning: building Windows agents without embedded smartctl"; fi

for t in $TARGETS; do
  os="${t%/*}"; arch="${t#*/}"
  name="inventory-agent-${os}-${arch}"
  tags=""
  ext=""
  extra_ld=""
  if [ "$os" = "windows" ]; then
    ext=".exe"
    extra_ld="-H windowsgui"
    if [ "$HAVE_SMARTCTL" = "1" ]; then
      mkdir -p internal/agent/assets
      if [ "$arch" = "amd64" ]; then
        cp "$SMART_DIR/bin/smartctl.exe" internal/agent/assets/smartctl.exe
      else
        # No ARM64 build of smartctl exists; x86 runs emulated on Windows on ARM.
        cp "$SMART_DIR/bin32/smartctl.exe" internal/agent/assets/smartctl.exe
      fi
      tags="-tags smartctl_embed"
    fi
  fi
  echo "building ${name}${ext}"
  # shellcheck disable=SC2086
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM=6 go build -trimpath $tags \
    -ldflags "$LDFLAGS $extra_ld" -o "$OUT/${name}${ext}" ./cmd/inventory-agent
done
rm -f internal/agent/assets/smartctl.exe

go run ./cmd/inventory-release manifest -dir "$OUT" -version "$VERSION" ${REQUIRE_SIGNATURE:+-require-signature}
