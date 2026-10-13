# observability module (M6.4+)

Dedicated CloudWatch log group, customer-managed KMS key, and configuration for AWS Distro for OpenTelemetry (ADOT) metrics collection.

## Purpose

This module provisions:
- `/aws/ecs/rag-platform-<env>/metrics`: Dedicated CloudWatch Log Group for Embedded Metric Format (EMF) logs.
- Dedicated customer-managed KMS key and alias with 1-to-1 log group encryption context enforcement.
- Rendered ADOT collector configuration (`adot_collector_config`) loaded in-memory via `AOT_CONFIG_CONTENT`.

Metrics flow via OTLP/HTTP from the application container to the local ADOT sidecar on `localhost:4318`. The ADOT collector's `awsemf` exporter serializes metrics to CloudWatch Logs via `PutLogEvents` over the existing private VPC endpoint for `logs`. CloudWatch automatically extracts and publishes metrics into the `SecureRAGPlatform` custom namespace.

## Security Constraints & Isolation

- **KMS 1-to-1 Encryption Context Enforcement:** All metrics logs are encrypted at rest with a dedicated customer-managed KMS key with annual rotation (`enable_key_rotation = true`). The key policy restricts use to `ArnEquals: { "kms:EncryptionContext:aws:logs:arn": local.metrics_log_group_arn }`.
- **In-Memory Configuration Delivery:** Delivered entirely via `AOT_CONFIG_CONTENT` environment variable, avoiding disk persistence and enabling `readonlyRootFilesystem: true`.
- **VPC Endpoint Re-use:** Zero new VPC endpoints are required (reuses private `com.amazonaws.<region>.logs` endpoint).
- **Network Isolation:** All OTLP communication occurs over task loopback (`localhost:4318`). Ports 4318 and 13133 have zero security group ingress rules and cannot be reached from outside the task ENI.
- **Fail-Closed Privacy:** Prometheus and EMF pipelines drop all resource attributes (including `service.instance.id`). Prompts, answers, chunks, tenant IDs, document IDs, request IDs, database URLs, and exception messages are never included in metric dimensions or EMF logs.

## Metric Dimension & Cardinality Strategy

- **Dimension Rollup Disabled:** Configured with `dimension_rollup_option: "NoDimensionRollup"` to eliminate automatic dimension permutations and cost explosion.
- **error.type Dimension Decision (Decision A):** Keeping error.type out of custom metric dimensions avoids additional custom metric-series cardinality and metric cost. CloudWatch Logs Insights can be used for on-demand error-type analysis, subject to normal Logs Insights query charges.
- **EMF Field & Trace Context Reality:**
  - Bounded metric attributes such as `outcome`, `role`, `operation`, `model`, `event`, etc. are expected in EMF according to the metric declaration and exporter behavior.
  - `error.type` may remain available as a non-dimension field only if proven by live output.
  - `trace_id` and `span_id` presence is UNVERIFIED until the live M6.4 smoke test inspects an actual EMF event. Metrics and traces are separate OpenTelemetry signals, and trace/span context is not guaranteed to be serialized into `awsemf` output merely because a metric was recorded inside an active span.
  - Do not design M6.5 Logs Insights correlation around `trace_id`/`span_id` unless live evidence proves they exist.

## ECS Sidecar Startup & Health Contract

- **ADOT Health Check:** Uses the statically compiled `/healthcheck` Go binary built into the ADOT image probing `http://localhost:13133/` with `interval = 30`, `timeout = 5`, `retries = 3`, and `startPeriod = 15`.
- **Collector Essential Policy (`essential = true`):** Both `app` and `aws-otel-collector` have `essential = true`. Telemetry is a required task-level security and operational control; if the collector container terminates, the entire task terminates and ECS Fargate replaces it, preventing silent unmonitored execution.
- **Startup Dependency (`condition: "START"`):** The application container specifies `dependsOn = [{ containerName = "aws-otel-collector", condition = "START" }]`. Using `START` rather than `HEALTHY` guarantees the collector process is running before the application initializes, while preventing startup deadlocks and startup delay during healthcheck stabilization.
- **Container Hardening:** Both containers run with `readonlyRootFilesystem = true`, drop all Linux capabilities (`ALL`), and run as non-root users (`app` and `aoc` / UID 4317).
- **Resource Allocations & CPU Shares:**
  - Task size: 512 CPU / 2048 MiB memory.
  - Application (`app`): `cpu = 384` (75% relative CPU share under contention), `memoryReservation = 1536` MiB.
  - Collector (`aws-otel-collector`): `cpu = 128` (25% relative CPU share under contention), `memoryReservation = 256` MiB, `memory = 512` MiB hard limit.
  - Both containers can burst into available CPU capacity according to standard ECS Fargate scheduling when the other is idle.

## Image Provenance & Digest Policy

- **Upstream Source Evidence:** `public.ecr.aws/aws-observability/aws-otel-collector:v0.50.0` with verified linux/amd64 digest `sha256:d0a012252142c0999982fc34cddc88e2f9ce8c6b2bdf2c53e8e489a49dfbac31` (rejected due to 7 unignored HIGH CVEs).
- **Project-Built Patched Image:** Derived from official `aws-observability/aws-otel-collector` commit `7579e0913cc764588c356a61616d6bca021f6b8d` (tag `v0.50.0`) with updated Go 1.26.9 toolchain and security-patched networking dependencies. Pushed to private ECR as `v0.50.0-patched.1`.
- **Private Mirror Digest Policy:** The task definition never references public ECR or tags. Operators mirror or build the image into the private `rag-platform-adot` repository, query the actual private digest via `aws ecr describe-images`, and configure `var.adot_image_digest` to that exact private digest. Upstream and private digests are documented as separate evidence fields.
- **Signing Status:** Container image signing remains **NOT CONFIGURED** (project does not yet maintain a private signing key).

## Two-Phase Deployment Sequence (Never Reuse Stale Plans)

Execute from the repository root:

1. **Phase 1 — Prerequisite Infrastructure (COMPLETED):**
   ```bash
   cd infrastructure/environments/dev
   terraform plan -target=module.ecr_adot -target=module.observability -out=tfplan-prereqs
   terraform apply tfplan-prereqs
   cd ../../..
   ```
   *Note: Prerequisite ECR, log group, and KMS keys were created. ECS task definition and service remained on their pre-M6.4 state.*

2. **Phase 2 — Patched Image Build & Push to Private ECR:**
   ```powershell
   # Build patched image locally from repository definition
   docker build --no-cache --platform linux/amd64 -t adot-patched:v0.50.0-patched.1 -f tools/adot/Dockerfile tools/adot

   # Authenticate and push to private ECR repository
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 376129869231.dkr.ecr.us-east-1.amazonaws.com
   docker tag adot-patched:v0.50.0-patched.1 376129869231.dkr.ecr.us-east-1.amazonaws.com/rag-platform-adot:v0.50.0-patched.1
   docker push 376129869231.dkr.ecr.us-east-1.amazonaws.com/rag-platform-adot:v0.50.0-patched.1

   # Query and capture actual private digest
   PRIVATE_DIGEST=$(aws ecr describe-images --repository-name rag-platform-adot --image-ids imageTag=v0.50.0-patched.1 --query 'imageDetails[0].imageDigest' --output text)
   ```
3. **Phase 3 — Fresh Full Plan & Apply:**
   ```bash
   # Generate fresh plan from environment directory
   cd infrastructure/environments/dev
   terraform plan -var="adot_image_digest=${PRIVATE_DIGEST}" -out=tfplan-final
   terraform show -json tfplan-final > tfplan-final.json
   cd ../../..

   # Validate policy gates on fresh plan from repository root (where policy/ directory resides)
   docker run --rm -v "${PWD}:/project" -w /project \
     openpolicyagent/conftest:v0.68.2@sha256:5fd81e332d7e4bc01daf3ef35371800a9a9720a30c0c37a78de0c5fbe4b6d622 \
     test --policy policy/terraform infrastructure/environments/dev/tfplan-final.json

   # Apply only the freshly verified plan
   cd infrastructure/environments/dev
   terraform apply tfplan-final
   cd ../../..
   ```
