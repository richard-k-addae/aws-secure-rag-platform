# ==============================================================================
# Patched AWS Distro for OpenTelemetry (ADOT) Collector
# Derived from official upstream: aws-observability/aws-otel-collector
# Tag: v0.50.0
# Target Commit: 7579e0913cc764588c356a61616d6bca021f6b8d
#
# Purpose:
# Replaces vulnerable Go stdlib and networking modules with security-patched
# versions (Go 1.26.9, golang.org/x/crypto v0.57.0, golang.org/x/net v0.60.0,
# google.golang.org/grpc v1.83.2) while strictly preserving ADOT v0.50.0 components,
# AOT_CONFIG_CONTENT support, and runtime behavior.
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Base Stage (OS user setup and root certificates)
# Pinned Alpine 3.21 digest
# ------------------------------------------------------------------------------
FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507 AS base

ARG USERNAME=aoc
ARG USER_UID=4317

RUN addgroup -g ${USER_UID} ${USERNAME} && \
    adduser -D -g ${USERNAME} -h "/home/${USERNAME}" -G ${USERNAME} -u ${USER_UID} ${USERNAME}

RUN apk --update --no-scripts add ca-certificates && \
    update-ca-certificates

# ------------------------------------------------------------------------------
# Stage 2: Builder Stage (Checkout, verify commit, patch, compile)
# Pinned Go 1.26.9 builder digest
# ------------------------------------------------------------------------------
FROM golang:1.26@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS builder

WORKDIR /workspace

ARG UPSTREAM_REPO=https://github.com/aws-observability/aws-otel-collector.git
ARG UPSTREAM_TAG=v0.50.0
ARG EXPECTED_COMMIT=7579e0913cc764588c356a61616d6bca021f6b8d

# 1. Clone official source at declared release tag
RUN git clone --depth 1 --branch ${UPSTREAM_TAG} ${UPSTREAM_REPO} /workspace

# 2. Refuse to build if checked-out HEAD differs from the locked release commit
RUN HEAD_COMMIT=$(git rev-parse HEAD) && \
    echo "Cloned HEAD commit: ${HEAD_COMMIT}" && \
    if [ "${HEAD_COMMIT}" != "${EXPECTED_COMMIT}" ]; then \
        echo "FATAL: Checked-out commit ${HEAD_COMMIT} does not match expected ${EXPECTED_COMMIT}" && exit 1; \
    fi

# 3. Apply committed minimal security patch (updates go.mod/go.sum and fixes alertmanager checksum)
COPY patches/adot-v0.50.0-security.patch /workspace/adot-v0.50.0-security.patch
RUN git apply --verbose /workspace/adot-v0.50.0-security.patch && \
    rm -f /workspace/adot-v0.50.0-security.patch

# 4. Remove stale vendor directory, download verified modules, and verify checksum database
RUN rm -rf vendor && \
    go mod download && \
    go mod verify

# 5. Build awscollector and healthcheck with deterministic compilation flags
RUN mkdir -p /workspace/bin && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /workspace/bin/awscollector ./cmd/awscollector && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /workspace/bin/healthcheck ./cmd/healthcheck

# 6. Prepare default upstream configuration files for /etc
RUN mkdir -p /workspace/etc && \
    cp /workspace/config.yaml /workspace/etc/otel-config.yaml && \
    cp -r /workspace/config/* /workspace/etc/

# ------------------------------------------------------------------------------
# Stage 3: Runtime Stage
# Scratch image containing only compiled binaries, user credentials, and certs
# ------------------------------------------------------------------------------
FROM scratch

ARG USERNAME=aoc

COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=base /etc/passwd /etc/passwd
COPY --from=base /etc/group /etc/group
COPY --from=base --chown=$USERNAME:$USERNAME /home/$USERNAME/ /home/$USERNAME
COPY --from=builder /workspace/bin/awscollector /awscollector
COPY --from=builder /workspace/bin/healthcheck /healthcheck
COPY --from=builder /workspace/etc/ /etc/

ENV RUN_IN_CONTAINER="True"

USER $USERNAME
ENV HOME=/home/$USERNAME
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/healthcheck"]
ENTRYPOINT ["/awscollector"]
CMD ["--config=/etc/otel-config.yaml"]
EXPOSE 4317 55681 2000
