# Patched ADOT Collector Build

This directory contains the reproducible, repository-controlled build definition for the patched AWS Distro for OpenTelemetry (ADOT) Collector image used by the platform's ECS tasks.

## Provenance Statement

**Project-built patched ADOT derived from official AWS ADOT v0.50.0 source.**

This artifact is **not** the untouched AWS-published container image. It is compiled directly from the official AWS release tag and commit, applying only minimal security patches to eliminate high-severity vulnerabilities in Go standard library and networking dependencies without modifying collector components, configurations, or runtime semantics.

## Upstream Release Metadata

| Field | Value |
|---|---|
| Upstream Repository | [aws-observability/aws-otel-collector](https://github.com/aws-observability/aws-otel-collector) |
| Release Tag | `v0.50.0` |
| Release Commit | `7579e0913cc764588c356a61616d6bca021f6b8d` |
| Upstream Published Image | `public.ecr.aws/aws-observability/aws-otel-collector:v0.50.0` |
| Upstream Image Digest | `sha256:d0a012252142c0999982fc34cddc88e2f9ce8c6b2bdf2c53e8e489a49dfbac31` |
| Upstream Toolchain | Go 1.24.13 |
| Core / Contrib Version | `v0.158.0` |

## Reason Official Image Was Rejected

During M6.4 Phase 3 pre-deployment security scanning with Trivy (v0.70.0), the official upstream image failed the security gate with **7 unignored HIGH-severity vulnerabilities**:

| CVE | Affected Component | Upstream Version | Fixed Version | Link Status |
|---|---|---|---|---|
| `CVE-2026-56854` | `golang.org/x/crypto` | `v0.54.0` | `v0.55.0` (`v0.57.0` used) | Linked in `awscollector` |
| `CVE-2026-78669` | `golang.org/x/net` / stdlib | `v0.57.0` | `v0.59.0` (`v0.60.0` used) | Linked in `awscollector` |
| `CVE-2026-84304` | `google.golang.org/grpc` | `v1.83.0` | `v1.83.2` | Linked in `awscollector` |
| `CVE-2026-84445` | `google.golang.org/grpc` | `v1.83.0` | `v1.83.2` | Linked in `awscollector` |
| `CVE-2026-78667` | Go stdlib (`crypto/x509`) | `1.24.13` | `1.26.9` | Linked in both binaries |
| `CVE-2026-78669` | Go stdlib (`net/http`) | `1.24.13` | `1.26.9` | Linked in both binaries |
| `CVE-2026-97031` | Go stdlib (`archive/zip`) | `1.24.13` | `1.26.9` | Linked in both binaries |

Per project policy, deploying unpatched HIGH CVEs is prohibited, and adding blanket ignore rules to `.trivyignore.yaml` was rejected.

## Security Changes in Patched Build

The build applies `patches/adot-v0.50.0-security.patch` to the official source checkout:

1. **Toolchain / Runtime Upgrade**: Replaced builder Go compiler from `1.24.13` to `go1.26.9` (`golang:1.26@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89`). This resolves `CVE-2026-78667`, `CVE-2026-78669`, and `CVE-2026-97031` across both `awscollector` and `healthcheck`.
2. **`golang.org/x/crypto`**: Upgraded `v0.54.0` -> `v0.57.0` (resolves `CVE-2026-56854`).
3. **`golang.org/x/net`**: Upgraded `v0.57.0` -> `v0.60.0` (resolves `CVE-2026-78669`).
4. **`google.golang.org/grpc`**: Upgraded `v1.83.0` -> `v1.83.2` (resolves `CVE-2026-84304` and `CVE-2026-84445`).
5. **Transitive Sub-dependencies**: Upgraded `golang.org/x/sys` (`v0.48.0`), `golang.org/x/mod` (`v0.41.0`), `golang.org/x/sync` (`v0.23.0`), `golang.org/x/term` (`v0.46.0`), `golang.org/x/text` (`v0.42.0`), `golang.org/x/tools` (`v0.49.0`) strictly as required by the 3 direct bumps.
6. **`alertmanager` Checksum Alignment**: Corrected the `go.sum` entry for `github.com/prometheus/alertmanager v0.33.0`.

## Investigation of `alertmanager` Checksum Discrepancy

When running `go mod download` on untouched upstream ADOT v0.50.0 source, the Go toolchain reported:

```text
verifying github.com/prometheus/alertmanager@v0.33.0: checksum mismatch
  downloaded: h1:AAVa3wpCsaDxisTUUPXx+1qhnA2mx0f8Cc+smpAtN7w=
  go.sum:     h1:Ea0jsa4kCLwz2E/9PGhkkBTIam8yFBPwvgsKZnJbojo=
```

### Root Cause Analysis

1. **Official Checksum Database Query**:
   `curl -s https://sum.golang.org/lookup/github.com/prometheus/alertmanager@v0.33.0`
   Returns record #55550380:
   `github.com/prometheus/alertmanager v0.33.0 h1:AAVa3wpCsaDxisTUUPXx+1qhnA2mx0f8Cc+smpAtN7w=`
2. **Upstream Contrib Comparison**:
   `open-telemetry/opentelemetry-collector-contrib` tag `v0.158.0` records `h1:AAVa3wpCsaDxisTUUPXx+1qhnA2mx0f8Cc+smpAtN7w=`.
3. **Upstream ADOT Git History**:
   ADOT commit `8f497cf49` (PR #3232) committed the erroneous hash `h1:Ea0jsa4kCLwz2E/9PGhkkBTIam8yFBPwvgsKZnJbojo=`.
4. **Why Upstream CI Missed It**:
   Upstream ADOT builds using pre-vendored source trees (`-mod=vendor`). The `go mod download` checksum database check was never invoked during upstream's release builds.
5. **Conclusion**:
   The downloaded module hash matches the official Go checksum database. Updating `go.sum` to `h1:AAVa3wpCsaDxisTUUPXx+1qhnA2mx0f8Cc+smpAtN7w=` is safe, correct, and enables `go mod verify` to pass cleanly.

## Reproducible Build Instructions

The build is fully automated and deterministic via `Dockerfile`:

```powershell
docker build --no-cache -t adot-patched:v0.50.0-patched.1 -f tools/adot/Dockerfile tools/adot
```

### Verification Steps Performed in Build

1. Shallow clones `https://github.com/aws-observability/aws-otel-collector.git` at tag `v0.50.0`.
2. Verifies `git rev-parse HEAD` equals `7579e0913cc764588c356a61616d6bca021f6b8d`. The build aborts immediately on any mismatch.
3. Applies `patches/adot-v0.50.0-security.patch` using `git apply --verbose`.
4. Removes stale `vendor/` directory, runs `go mod download`, and runs `go mod verify`.
5. Compiles both binaries with deterministic flags:
   `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w"`
6. Assembles runtime `scratch` container with non-root user `aoc` (UID 4317).

## Binary Hash Reproducibility

Two independent builds executed from fresh checkouts produced identical binary SHA256 hashes:

| Binary | SHA256 Hash | Match |
|---|---|---|
| `awscollector` | `41AAF1B9BA0EB014551F3A491584FAFF4FAFD609403500FAC7B7D4031B721B41` | YES |
| `healthcheck` | `33DD0A9EA5CCD69C694B641A729BED29F4930B5884136691D6748D29E681C681` | YES |

## Component and Runtime Verification

The compiled collector binary was verified against:
- **Components**: `otlp` receiver (HTTP & gRPC), `memory_limiter`, `resource`, `batch` processors, `awsemf` exporter, `health_check` extension.
- **Dynamic Configuration**: `AOT_CONFIG_CONTENT` environment variable is fully supported.
- **Health Check**: `/healthcheck` binary functions against the collector's health_check extension endpoint (`:13133`).
- **Filesystem**: Fully operational with `--read-only` root filesystem.
- **Identity**: Runs as non-root user `aoc` (UID 4317).
- **M6.4 Configuration**: Parsed and validated the exact rendered M6.4 Terraform collector configuration with CloudWatch EMF metric declarations.

## Security Scanning Evidence

Scanned with pinned Trivy:
`aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e`

```text
HIGH: 0
CRITICAL: 0
```

## Known Supply-Chain Gaps

- **Signing**: The image is unsigned. The platform currently has no container signing key (Cosign/Notary) established.
- **Recommended Tag**: `v0.50.0-patched.1` (deployment references immutable private ECR digest).
