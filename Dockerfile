# syntax=docker/dockerfile:1.7
#
# Talon image: multi-stage Go build, distroless static runtime.
#
# The image carries three binaries. The default entrypoint is /talon (the
# proxy). /svctoken-refresher and /posture-signer are started by overriding
# the command (see deploy/helm).
#
# Build args:
#   VERSION     - version string stamped into the binaries (default: dev)
#   VCS_REF     - git commit SHA
#   BUILD_DATE  - RFC 3339 build timestamp

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

RUN apk add --no-cache git ca-certificates

# Fetch modules first so this layer is cached until go.mod/go.sum change.
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY cmd/      cmd/
COPY internal/ internal/
COPY api/      api/

ARG TARGETOS=linux
ARG TARGETARCH
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=dev

# Static, stripped binaries; -X stamps build metadata into the main packages.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    for bin in talon svctoken-refresher posture-signer; do \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH:-$(go env GOARCH)} \
      go build -trimpath \
        -ldflags="-s -w \
          -X main.version=${VERSION} \
          -X main.commit=${VCS_REF} \
          -X main.buildDate=${BUILD_DATE}" \
        -o /out/${bin} ./cmd/${bin} || exit 1; \
    done

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=dev
LABEL org.opencontainers.image.title="talon" \
      org.opencontainers.image.description="Identity-aware reverse proxy (NIST SP 800-207 policy enforcement point)" \
      org.opencontainers.image.source="https://github.com/dogukanturhal/talon" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

COPY --from=build /out/talon              /talon
COPY --from=build /out/svctoken-refresher /svctoken-refresher
COPY --from=build /out/posture-signer     /posture-signer

USER 65532:65532
EXPOSE 8443 9090
ENTRYPOINT ["/talon"]
