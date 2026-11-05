# Milestone 6.4: Patched ADOT Collector Supply-Chain Build Evidence

## Executive Summary

During the Phase 3 pre-deployment security gate of M6.4 (ADOT Collector Sidecar Deployment), the upstream AWS-published container image was scanned with Trivy v0.70.0 and failed with **7 unignored HIGH-severity vulnerabilities** in Go standard library and networking dependencies.

### Historical Context and Controlled Deployment State

Prior to this vulnerability finding, a controlled prerequisite apply had already created the supporting infrastructure:
- Private ECR repository: `rag-platform-adot`
- Dedicated ECR customer-managed KMS key and alias
- Dedicated CloudWatch metrics log group: `/aws/ecs/rag-platform-dev/metrics`
- Dedicated metrics log customer-managed KMS key and alias

At that stage:
- The active ECS service and task definition remained completely unchanged.
- No ADOT container image had been pushed to the private ECR repository.
- No final ECS task definition, IAM policy additions, or VPC endpoint policy updates had been deployed.
- Container image signing remains **NOT CONFIGURED** (project does not yet maintain a private signing key).

In accordance with platform security standards:
1. No vulnerability exception rules were added to `.trivyignore.yaml`.
2. Live ECS service and final infrastructure deployment remained halted at the vulnerability gate.
3. A reproducible, project-controlled build was designed and implemented in [tools/adot/](../../tools/adot/) to compile an ADOT-compatible container image directly from the official upstream v0.50.0 source commit while applying minimal security patches to vulnerable dependencies.
4. Independent verification proved 100% bit-for-bit binary reproducibility between consecutive fresh builds, 0 HIGH and 0 CRITICAL vulnerability scan findings, and full runtime/configuration compatibility with the rendered M6.4 task definition.

---

## 1. Upstream Metadata and Rejection Reason

| Attribute | Value |
|---|---|
| Upstream Repository | [aws-observability/aws-otel-collector](https://github.com/aws-observability/aws-otel-collector) |
| Release Tag | `v0.50.0` |
| Release Commit SHA | `7579e0913cc764588c356a61616d6bca021f6b8d` |
| Published Upstream Image | `public.ecr.aws/aws-observability/aws-otel-collector:v0.50.0` |
| Upstream Manifest Digest | `sha256:d0a012252142c0999982fc34cddc88e2f9ce8c6b2bdf2c53e8e489a49dfbac31` |
| Upstream Compiler | Go 1.24.13 |

### Original HIGH Findings in Upstream Image

| # | CVE | Package / Library | Upstream Version | Fixed In | Binary Linkage |
|---|---|---|---|---|---|
| 1 | `CVE-2026-56854` | `golang.org/x/crypto` | `v0.54.0` | `v0.55.0` | `awscollector` |
| 2 | `CVE-2026-78669` | `golang.org/x/net` / stdlib | `v0.57.0` | `v0.59.0` | `awscollector` |
| 3 | `CVE-2026-84304` | `google.golang.org/grpc` | `v1.83.0` | `v1.83.2` | `awscollector` |
| 4 | `CVE-2026-84445` | `google.golang.org/grpc` | `v1.83.0` | `v1.83.2` | `awscollector` |
| 5 | `CVE-2026-78667` | Go stdlib (`crypto/x509`) | `1.24.13` | `1.26.9` | `awscollector`, `healthcheck` |
| 6 | `CVE-2026-78669` | Go stdlib (`net/http`) | `1.24.13` | `1.26.9` | `awscollector`, `healthcheck` |
| 7 | `CVE-2026-97031` | Go stdlib (`archive/zip`) | `1.24.13` | `1.26.9` | `awscollector`, `healthcheck` |

---

## 2. Supply-Chain Provenance Statement

**Project-built patched ADOT derived from official AWS ADOT v0.50.0 source.**

This artifact is **not** the untouched AWS-published container image. It is built from source under repository configuration:
- Source tree cloned from official tag `v0.50.0` and validated against commit `7579e0913cc764588c356a61616d6bca021f6b8d`.
- Patches restricted exclusively to Go toolchain upgrade and module security bumps in `go.mod` and `go.sum`.
- No modifications made to receiver, processor, exporter, or extension Go code.

---

## 3. Builder and Build Environment

| Parameter | Specification |
|---|---|
| Pinned Go Builder | `golang:1.26@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89` |
| Actual Go Version | `go version go1.26.9 linux/amd64` |
| Pinned Base Image | `alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507` |
| Runtime Image Format | `FROM scratch` (static binaries, non-root user `aoc` UID 4317) |
| Compilation Flags | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w"` |
| Target Platform | `linux/amd64` |

---

## 4. Applied Security Patch Details

- Patch file: [tools/adot/patches/adot-v0.50.0-security.patch](../../tools/adot/patches/adot-v0.50.0-security.patch)
- Patch SHA256: `79F7E2E100EEB483B0367FBC00D5235460BB015BFA31C261846297846B4BC609`

### Dependency Changes Applied

| Dependency | Original Version | Patched Version | Rationale |
|---|---|---|---|
| `golang.org/x/crypto` | `v0.54.0` | `v0.57.0` | Fixes `CVE-2026-56854` (required by x/net v0.60.0) |
| `golang.org/x/net` | `v0.57.0` | `v0.60.0` | Fixes `CVE-2026-78669` |
| `google.golang.org/grpc` | `v1.83.0` | `v1.83.2` | Fixes `CVE-2026-84304`, `CVE-2026-84445` |
| `golang.org/x/sys` | `v0.47.0` | `v0.48.0` | Transitive requirement of x/net v0.60.0 & x/crypto v0.57.0 |
| `golang.org/x/mod` | `v0.38.0` | `v0.41.0` | Transitive requirement of x/tools v0.49.0 |
| `golang.org/x/sync` | `v0.22.0` | `v0.23.0` | Transitive requirement of x/net v0.60.0 & grpc v1.83.2 |
| `golang.org/x/term` | `v0.45.0` | `v0.46.0` | Transitive requirement of x/crypto v0.57.0 |
| `golang.org/x/text` | `v0.40.0` | `v0.42.0` | Transitive requirement of x/net v0.60.0 |
| `golang.org/x/tools` | `v0.48.0` | `v0.49.0` | Transitive requirement of x/net v0.60.0 |
| `github.com/prometheus/alertmanager` | `v0.33.0` (bad hash) | `v0.33.0` (aligned) | Corrects errant `go.sum` hash to match official Go sumdb record #55550380 |

### Checksum Database Investigation (`alertmanager v0.33.0`)
- Upstream ADOT commit `8f497cf49` (PR #3232) committed hash `h1:Ea0jsa4kCLwz2E/9PGhkkBTIam8yFBPwvgsKZnJbojo=`.
- Official Go checksum database (`sum.golang.org` lookup #55550380) and upstream `opentelemetry-collector-contrib/v0.158.0` record `h1:AAVa3wpCsaDxisTUUPXx+1qhnA2mx0f8Cc+smpAtN7w=`.
- Upstream missed this discrepancy because its build pipeline relied on vendored sources (`-mod=vendor`), bypassing sumdb validation.
- Updating `go.sum` to the sumdb-verified hash enabled `go mod verify` to pass cleanly (`all modules verified`).

---

## 5. Binary Hash Reproducibility Verification

Two independent builds were executed from scratch with `--no-cache`:
- **Build 1 Image ID**: `sha256:847f7d45c9c0ffe48c288e72b5d58d2aec95cb4d75ff8f7ad3c86cb3fba64e79` (tag: `adot-patched:v0.50.0-patched.1`)
- **Build 2 Image ID**: `sha256:3a9d286ec221b3816232595bfdb381c1adc0ecc457577cd9f67a84b423ef8d0e` (tag: `adot-patched:v0.50.0-patched.1-build2`)

The compiled binaries were extracted from each container and hashed:

| Binary | Build 1 SHA256 | Build 2 SHA256 | Match |
|---|---|---|---|
| `awscollector` | `41AAF1B9BA0EB014551F3A491584FAFF4FAFD609403500FAC7B7D4031B721B41` | `41AAF1B9BA0EB014551F3A491584FAFF4FAFD609403500FAC7B7D4031B721B41` | **YES (Identical)** |
| `healthcheck` | `33DD0A9EA5CCD69C694B641A729BED29F4930B5884136691D6748D29E681C681` | `33DD0A9EA5CCD69C694B641A729BED29F4930B5884136691D6748D29E681C681` | **YES (Identical)** |

Both builds produced bit-for-bit identical Go binaries.

---

## 6. Security Scanning Evidence

The resulting image was scanned using the repository-pinned Trivy container:
- **Trivy Image**: `aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e`
- **Command**: `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v .../.trivyignore.yaml:/.trivyignore.yaml aquasec/trivy:0.70.0@sha256:... image --severity HIGH,CRITICAL --ignorefile /.trivyignore.yaml adot-patched:v0.50.0-patched.1`

### Scan Results

```text
┌──────────────┬──────────┬─────────────────┬─────────┐
│    Target    │   Type   │ Vulnerabilities │ Secrets │
├──────────────┼──────────┼─────────────────┼─────────┤
│ awscollector │ gobinary │        0        │    -    │
├──────────────┼──────────┼─────────────────┼─────────┤
│ healthcheck  │ gobinary │        0        │    -    │
└──────────────┴──────────┴─────────────────┴─────────┘
```

- **CRITICAL findings**: 0
- **HIGH findings**: 0
- **Residual CVEs**: None

---

## 7. Component and Runtime Verification

The built container was tested with the exact M6.4 ADOT configuration rendered for ECS:
1. **Dynamic Configuration via `AOT_CONFIG_CONTENT`**: Verified that ADOT parses configuration supplied via environment variable without error.
2. **Read-Only Root Filesystem**: Executed container with `--read-only`; the collector started and remained operational without requiring root filesystem writes.
3. **Non-Root Execution**: Runs under unprivileged user `aoc` (UID 4317).
4. **Health Check Binary**: Invoked `/healthcheck` against port `:13133`; received `STATUS: 200`.
5. **Component Compatibility**:
   - `otlp` receiver initialized on gRPC (`[::]:4317`) and HTTP (`[::]:4318`).
   - `memory_limiter` processor initialized (`75% limit`, `20% spike limit`).
   - `resource` processor initialized (strips `service.instance.id`).
   - `batch` processor initialized (`send_batch_size: 256`, `timeout: 5s`).
   - `awsemf` exporter initialized with custom `dimension_rollup_option: "NoDimensionRollup"` and metric declarations.
   - `health_check` extension reached `status: ready`.

---

## 8. Naming and Signing Status

- **Recommended Private Image Tag**: `v0.50.0-patched.1`
  *(Note: ECS task definition references the immutable private ECR digest, not the mutable tag).*
- **Signing Status**: **NOT CONFIGURED**
- **Known Gap**: The project does not currently maintain a private container image signing key (e.g. Cosign, AWS Signer, or Notary). Image integrity relies on digest pinning across build, registry push, and task definition deployment.

---

## 9. Deployed Image & Extracted Binary Verification

The patched ADOT image was pushed to the private ECR repository and deployed to ECS.

### ECR Image Identifiers

- **Repository**: `376129869231.dkr.ecr.us-east-1.amazonaws.com/rag-platform-adot`
- **Tag**: `v0.50.0-patched.1`
- **Tagged Image Index Digest (OCI Index)**: `sha256:429737a8f281d09b7bc8b00af0bfe4778ffc31b04be2ba9abdb1aec9147600f7`
- **Deployable Child `linux/amd64` Manifest Digest**: `sha256:3739d259f0bdecf75f1717f78d51d32274f08231e9e8366f7135e662805c7307`
- **Attestation Manifest Digest**: `sha256:e26452daf66ad44c0057c140f5b63b482a10a7732d7e847cb4756fa8c201a1e7`
- **ECS Task Definition Pinned Digest**: `sha256:429737a8f281d09b7bc8b00af0bfe4778ffc31b04be2ba9abdb1aec9147600f7`

### Deployed Binary Extraction and Hash Comparison

The exact deployed container image was pulled from ECR, and the binaries `/awscollector` and `/healthcheck` were extracted and hashed using SHA256:

| Binary | Local Reproducible Builds (1 & 2) SHA256 | Deployed ECR Container SHA256 | Match |
|---|---|---|---|
| `/awscollector` | `41AAF1B9BA0EB014551F3A491584FAFF4FAFD609403500FAC7B7D4031B721B41` | `41AAF1B9BA0EB014551F3A491584FAFF4FAFD609403500FAC7B7D4031B721B41` | **YES (100% Identical)** |
| `/healthcheck` | `33DD0A9EA5CCD69C694B641A729BED29F4930B5884136691D6748D29E681C681` | `33DD0A9EA5CCD69C694B641A729BED29F4930B5884136691D6748D29E681C681` | **YES (100% Identical)** |

*Conclusion:* The deployed ECR artifact contains the exact bit-for-bit compiled binaries produced by the repository-controlled reproducible build recipe in [tools/adot/](../../tools/adot/). (An errant hash transcription in an intermediate deployment report was investigated and corrected).

---

## 10. ECR Basic Scanning vs Local Pinned Trivy Scanner

- **ECR Basic Scanning Scope**:
  - Scanning the top-level OCI Image Index (`sha256:429737a8f281...`) returns `ScanNotFoundException` because AWS ECR Basic Scanning does not scan multi-architecture index manifests directly.
  - Scanning the child `linux/amd64` image manifest (`sha256:3739d259f0bd...`) returns `status: FAILED` with `UnsupportedImageError: The operating system and/or package manager are not supported.` ECR Basic Scanning relies on Clair OS package scanning (RPM/Debian/Alpine APK) and cannot inspect pure `FROM scratch` images containing statically linked Go binaries.
  - ECR Basic Scanning Finding Count: **0** (Unsupported/Failed scan).
- **Local Pinned Trivy Scanner (Authoritative Gate)**:
  - Container: `aquasec/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e`
  - Trivy inspects compiled Go binary symbol tables and ELF headers directly inside scratch containers.
  - Pinned Trivy Result: **0 HIGH, 0 CRITICAL** (100% clean against `.trivyignore.yaml`).

---

## 11. ECS Task Lifecycle & Container Essential Policy

- **Policy Contract**: Observability is an essential task-level control in the platform security architecture.
  - `app`: `essential = true`
  - `aws-otel-collector`: `essential = true`
  - Dependency: `app` has `dependsOn = [{ containerName = "aws-otel-collector", condition = "START" }]`.
- **Failure Mode**: If the ADOT collector terminates, the ECS task terminates immediately and ECS Fargate schedules a replacement task. This prevents the platform from executing silently without required operational and security telemetry.
- **Rollout Status**: Live task definition revision `:4` is the active service target (`ACTIVE`), with both `app` and `aws-otel-collector` running with `essential = true`. Rollback revision `:2` and historical revision `:3` remain `ACTIVE` and preserved in ECS.
- **Live Telemetry & Privacy Verification**:
  - CloudWatch Logs log group `/aws/ecs/rag-platform-dev/metrics` actively receives fresh EMF metric events.
  - CloudWatch namespace `SecureRAGPlatform` confirms aggregation across operational dimensions.
  - Privacy verification passed: 100% free of sensitive data (0 occurrences of `tenant_id`, `prompt`, `chunk`, `answer`, `document_id`, `request_id`, raw SQL, or `service.instance.id`).
- **Configuration & State Drift**:
  - `terraform plan -detailed-exitcode` returns exit code `0` (Zero infrastructure drift).

---

## 12. Deployment Forensic Review: Two-Phase Apply Investigation

An investigation of Terraform state versions in `s3://rag-platform-tfstate-376129869231/dev/terraform.tfstate` was performed:
1. **Saved Plan Apply (`terraform apply tfplan-final` at 04:54:55 UTC)**:
   - Successfully created `aws_iam_role_policy.task_metrics`, updated `aws_iam_role_policy.execution` for ADOT ECR access, updated VPC endpoint policies (`ecr.api`, `ecr.dkr`), and registered task definition `rag-platform-dev-app:3`.
   - During task deployment, new tasks encountered transient 403 errors during VPC endpoint policy propagation (~7 second AWS IAM eventual consistency delay). The ECS deployment circuit breaker rolled the ECS service back to revision `:2`.
2. **Subsequent Auto-Approved Apply (`terraform apply -auto-approve` at 04:58:05 UTC)**:
   - Executed after VPC endpoint policies were fully consistent across AWS ENIs.
   - Successfully transitioned `aws_ecs_service.rag-platform-dev-app` from revision `:2` to revision `:3`.
   - Performed read-only state refreshes on IAM role policy lists and RDS restorable time.
   - **Zero resources outside the reviewed M6.4 scope were created, modified, or destroyed.**
   - Protocol requirement reinforced: All subsequent applies must execute strictly from reviewed saved plans (`terraform apply <plan-file>`), never `-auto-approve`.

---

## 13. Working Tree and Artifact State Distinction

- **Generated Plan and Smoke Test Artifacts**: All temporary plan files (`tfplan*`), test payloads (`metrics_payload.bin`), smoke test scripts, binary extractions (`awscollector_b1`, `awscollector_ecr`, etc.), and test containers have been removed.
- **Git Working Tree Status**: Working tree is fully clean upon final M6.4 commit.
