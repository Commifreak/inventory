# syntax=docker/dockerfile:1.7
#
# Container image of the Home Assistant add-on "Inventory Agent"
# (ghcr.io/commifreak/inventory-ha-agent), multi-arch: linux/amd64,
# linux/arm64, linux/arm/v7. Built by the release workflow for vX.Y.Z tags;
# the add-on definition lives in github.com/Commifreak/inventory-ha-addon.

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM="${TARGETVARIANT#v}" go build -trimpath \
    -ldflags "-s -w -X github.com/commifreak/inventory/internal/agent.Version=${VERSION:-0.0.0-dev}" \
    -o /out/inventory-agent ./cmd/inventory-agent

FROM debian:bookworm-slim
# smartmontools: disk health; systemd: journalctl for the host journal
# (mounted by Home Assistant); util-linux: lsblk, dmesg.
RUN apt-get update \
 && apt-get install -y --no-install-recommends smartmontools systemd util-linux ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ARG VERSION
LABEL io.hass.type="addon" \
      io.hass.version="${VERSION}" \
      org.opencontainers.image.title="Inventory Agent (Home Assistant add-on)" \
      org.opencontainers.image.source="https://github.com/commifreak/inventory" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/inventory-agent /usr/local/bin/inventory-agent
ENTRYPOINT ["/usr/local/bin/inventory-agent", "addon"]
