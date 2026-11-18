# syntax=docker/dockerfile:1.7
#
# Multi-arch image (linux/amd64, linux/arm64). All Go builds are
# cross-compiled on the build platform, so no emulation is needed.
#
# The agent binaries are signed when the BuildKit secret
# "release_signing_key" is provided (CI). Local builds without it produce
# unsigned agents: installation works, automatic updates do not.

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS base
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

FROM base AS agents
RUN apt-get update && apt-get install -y --no-install-recommends p7zip-full && rm -rf /var/lib/apt/lists/*
ARG VERSION
ARG EXTRA_TRUSTED_KEY
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=release_signing_key,required=false \
    VERSION="${VERSION:-0.0.0-dev}" RELEASE_SIGNING_KEY_FILE=/run/secrets/release_signing_key \
    EXTRA_TRUSTED_KEY="${EXTRA_TRUSTED_KEY}" ./scripts/build-agents.sh \
 && mkdir -p /out && cp -r dist/agents /out/agents

FROM base AS server
ARG VERSION
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION:-0.0.0-dev}" -o /out/inventory-server ./cmd/inventory-server \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="Inventory" \
      org.opencontainers.image.description="Inventory, disk health and update monitoring for Windows, Linux and macOS clients" \
      org.opencontainers.image.source="https://github.com/commifreak/inventory" \
      org.opencontainers.image.licenses="MIT"
COPY --from=server /out/inventory-server /app/inventory-server
COPY --from=agents /out/agents /app/agents
COPY --from=server --chown=65532:65532 /out/data /data
ENV DATA_DIR=/data AGENTS_DIR=/app/agents LISTEN_ADDR=:8080
EXPOSE 8080
VOLUME ["/data"]
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/app/inventory-server", "healthcheck"]
ENTRYPOINT ["/app/inventory-server"]
