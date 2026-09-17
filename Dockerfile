# syntax=docker/dockerfile:1.7
#
# Talon Dockerfile — multi-stage Go build → distroless static.
#
# Build args set by .gitlab-ci.yml:
#   VCS_REF       — git SHA
#   BUILD_DATE    — RFC3339 timestamp
#   VERSION       — image tag (CI uses CI_COMMIT_SHA)

ARG GO_VERSION=1.26

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
# golang:<MAJOR.MINOR>-alpine resolves to the latest published patch; we
# pin via Dockerfile + Renovate later. mirror.gcr.io does NOT publish the
# old 3.20 tag for Go 1.26 — only -alpine (latest), -alpine3.22, and
# -alpine3.23 exist as of 2026-04-26.
FROM mirror.gcr.io/library/golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Private-module fetch for hexxlock-namespace deps (e.g. hexx-pep-core,
# ADR 0031). The default golang:alpine image ships without git, so go
# can't shell out for VCS fetches at all; add it before go mod download.
# Auth uses GITLAB_GOPROXY_PAT passed as build-arg (same token wired
# for the test/lint jobs); GOVCS skips Go's "?go-get=1" HTTP discovery
# that would 401 on private repos before any auth applies.
RUN apk add --no-cache git ca-certificates
    GOVCS=github.com:git,github.com:git

# GOPROXY plumbed in from CI so BuildKit's `go mod download` (below)
# hits the in-cluster Athens proxy instead of `proxy.golang.org`.
# Without this, each build pays minutes fetching modules over the
# BuildKit pod's internet egress and Athens never sees this traffic.
# `direct` fallback keeps `go mod download` working outside CI.
# Plumbed via shared-ci-templates build-service.yml `--opt build-arg:GOPROXY=…`.
ARG GOPROXY=direct
ENV GOPROXY=$GOPROXY
ARG GITLAB_GOPROXY_PAT
RUN if [ -n "${GITLAB_GOPROXY_PAT}" ]; then \
    fi

# Pre-fetch deps for better layer caching.
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy sources
COPY cmd/      cmd/
COPY internal/ internal/
COPY api/      api/

ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=dev

# Static, stripped binary. -s -w drops symbol+DWARF tables; -X injects
# build metadata into cmd/talon/main.go variables.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${VCS_REF} \
        -X main.buildDate=${BUILD_DATE}" \
      -o /out/talon ./cmd/talon

# Also build the svctoken-refresher sidecar binary into the same image.
# Embedding instead of shipping a separate image because:
#   1. The talon CI's SLSA chain (sign, scan, verify) covers EVERY binary
#      in the image — adding another image would mean cloning all 4 jobs.
#   2. image-updater already tracks the talon tag; no second
#      ArgoCD-image-updater config.
#   3. The refresher is a thin process whose lifecycle is identical to
#      the talon binary in any given deployment (rebuilt on the same
#      git SHA). Coupling at the image level reflects that contract.
# The talon container's ENTRYPOINT stays /talon; ArgoCD's sidecar uses
# command: ["/svctoken-refresher"] to override.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${VCS_REF} \
        -X main.buildDate=${BUILD_DATE}" \
      -o /out/svctoken-refresher ./cmd/svctoken-refresher

# Also build the posture-signer service binary into the same image
# (ZTNA Phase 4 — RS256 JWS issuer for HexxLock Access device-posture
# heartbeats). Same rationale as svctoken-refresher above:
#   1. SLSA sign/scan/verify chain covers EVERY binary in this image;
#      adding a separate posture-signer image would mean cloning the
#      build/sign/scan/verify jobs in .gitlab-ci.yml.
#   2. image-updater already tracks the talon tag; no second
#      argocd-image-updater config needed.
#   3. posture-signer's release cadence is tightly coupled to talon's
#      shared internal/ packages (posture verifier, audit, etc.).
# Chart override: posture-signer Deployment runs the container with
# `command: ["/posture-signer"]` overriding the default /talon
# ENTRYPOINT. See deploy/helm/posture-signer/templates/deployment.yaml.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${VCS_REF} \
        -X main.buildDate=${BUILD_DATE}" \
      -o /out/posture-signer ./cmd/posture-signer

# ---------------------------------------------------------------------------
# Runtime stage — distroless static for minimal CVE surface.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=dev
LABEL org.opencontainers.image.title="talon" \
      org.opencontainers.image.description="HexxLock identity-aware proxy for internal.example.com" \
      org.opencontainers.image.source="https://github.com/dogukanturhal/talon" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="proprietary"

COPY --from=build /out/talon              /talon
COPY --from=build /out/svctoken-refresher /svctoken-refresher
COPY --from=build /out/posture-signer     /posture-signer

USER 65532:65532
EXPOSE 8443 9090
ENTRYPOINT ["/talon"]
