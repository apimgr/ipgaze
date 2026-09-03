# =============================================================================
# Build Stage - Compile Go binary
# =============================================================================
FROM casjaysdev/go:latest AS builder

RUN apk add --no-cache git bash

ARG TARGETARCH
ARG VERSION=dev
# BUILD_EPOCH is the single embedded time source; BuildDate is derived from it at process start
ARG BUILD_EPOCH
ARG COMMIT_ID
ARG OFFICIAL_SITE=

WORKDIR /app

# Copy go.mod first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -buildvcs=false -trimpath \
    -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.CommitID=${COMMIT_ID}' -X 'main.BuildEpoch=${BUILD_EPOCH}' -X 'main.OfficialSite=${OFFICIAL_SITE}'" \
    -o /app/binary/ipgaze ./src

# =============================================================================
# Runtime Stage - Minimal Alpine image
# =============================================================================
FROM alpine:latest

# ARGs for build-time values (set by docker build --build-arg)
ARG VERSION=dev
ARG BUILD_DATE
ARG COMMIT_ID
ARG LICENSE=MIT

# No LABEL blocks — all image metadata is applied as OCI annotations at build time.
# Pass --annotation flags to docker buildx build (or use docker/metadata-action
# annotations: output in GitHub Actions). Annotations attach to the manifest index
# and are visible on multiarch pulls. LABEL applies only to per-platform layers.
# See dockerfile_conventions.md → OCI Annotations.

# Upgrade base packages first so transitively-pulled libs (e.g. libcrypto3/
# libssl3) get security fixes published after the alpine:latest layer was cut
RUN apk update && apk upgrade --no-cache

# Install required packages: git, curl, bash, tini, tor
RUN apk add --no-cache \
    git \
    curl \
    bash \
    tini \
    tor

# Copy binary from builder stage
COPY --from=builder /app/binary/ipgaze /usr/local/bin/ipgaze

# Copy build-time overlay (entrypoint.sh, config files, etc.) from docker/rootfs/
COPY docker/rootfs/ /

# Copy Dockerfile to image for reference
COPY docker/Dockerfile /root/Dockerfile

# Make all binaries/scripts in /usr/local/bin executable
RUN chmod 755 /usr/local/bin/*

# NO directory creation, NO non-root user - binary handles ALL setup based
# on env vars, including creating its own dedicated system user and
# dropping privileges after binding privileged ports (see AI.md PART 23).
# Docker volume mounts auto-create mount points.
# Documented non-root exception (AI.md PART 26, "document exception in
# IDEA.md" clause) — see IDEA.md "Docker non-root exception".
# trivy:ignore:AVD-DS-0002

# Container path conventions:
# Config: /config/ipgaze/   Data: /data/ipgaze/   DB: /data/db/sqlite/
# MODE is never baked into the image — binary defaults to production; compose sets MODE explicitly
ENV TZ=America/New_York \
    DATABASE_DIR=/data/db/sqlite

# Port 80 inside container (mapped by docker-compose)
EXPOSE 80

# SIGRTMIN+3 for graceful shutdown
STOPSIGNAL SIGRTMIN+3

# Health check — long start period for service initialization
HEALTHCHECK --start-period=10m --interval=5m --timeout=15s --retries=3 \
    CMD /usr/local/bin/ipgaze --status || exit 1

# tini as init with SIGTERM propagation; entrypoint handles signals
ENTRYPOINT [ "tini", "-p", "SIGTERM", "--", "/usr/local/bin/entrypoint.sh" ]
