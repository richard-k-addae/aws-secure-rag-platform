# M6.5B: CloudWatch dashboard for the secure RAG platform.
# Read-only visualization only — no new telemetry pipelines, no AMP/AMG/X-Ray.

locals {
  observability_cluster        = module.ecs.cluster_name
  observability_service        = module.ecs.service_name
  observability_namespace      = module.observability.namespace
  observability_dashboard_name = "rag-platform-${var.environment}-observability"

  ecs_dims = ["ClusterName", local.observability_cluster, "ServiceName", local.observability_service]
}

resource "aws_cloudwatch_dashboard" "observability" {
  dashboard_name = local.observability_dashboard_name

  dashboard_body = jsonencode({
    widgets = [
      # --- A. Platform Health -------------------------------------------------
      {
        type       = "text", x = 0, y = 0, width = 24, height = 1
        properties = { markdown = "## A. Platform Health" }
      },
      {
        type = "metric", x = 0, y = 1, width = 12, height = 6
        properties = {
          title  = "CPU / Memory Utilization (%)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            concat(["AWS/ECS", "CPUUtilization"], local.ecs_dims, [{ label = "CPUUtilization" }]),
            concat(["AWS/ECS", "MemoryUtilization"], local.ecs_dims, [{ label = "MemoryUtilization" }]),
          ]
        }
      },
      {
        type = "metric", x = 12, y = 1, width = 12, height = 6
        properties = {
          title  = "Running / Desired / Pending Tasks, Deployments"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            concat(["ECS/ContainerInsights", "RunningTaskCount"], local.ecs_dims, [{ label = "RunningTaskCount" }]),
            concat(["ECS/ContainerInsights", "DesiredTaskCount"], local.ecs_dims, [{ label = "DesiredTaskCount" }]),
            concat(["ECS/ContainerInsights", "PendingTaskCount"], local.ecs_dims, [{ label = "PendingTaskCount" }]),
            concat(["ECS/ContainerInsights", "DeploymentCount"], local.ecs_dims, [{ label = "DeploymentCount" }]),
          ]
        }
      },

      # --- B. RAG Query -----------------------------------------------------------
      {
        type       = "text", x = 0, y = 7, width = 24, height = 1
        properties = { markdown = "## B. RAG Query" }
      },
      {
        type = "metric", x = 0, y = 8, width = 12, height = 6
        properties = {
          title  = "rag.query.duration by outcome (avg, seconds)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.query.duration", "role", "reader", "outcome", "answered", { label = "answered (avg, seconds)" }],
            [local.observability_namespace, "rag.query.duration", "role", "reader", "outcome", "no_context", { label = "no_context (avg, seconds)" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 8, width = 12, height = 6
        properties = {
          title  = "rag.query.duration — Observed p95 — not an SLO (seconds)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "p95"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.query.duration", "role", "reader", "outcome", "answered", { label = "answered — observed p95 (seconds)" }],
            [local.observability_namespace, "rag.query.duration", "role", "reader", "outcome", "no_context", { label = "no_context — observed p95 (seconds)" }],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 14, width = 24, height = 6
        properties = {
          title  = "rag.query.retrieved_chunks (avg, count)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.query.retrieved_chunks", "role", "reader", { label = "retrieved_chunks (avg)" }],
          ]
        }
      },

      # --- C. Retrieval -----------------------------------------------------------
      {
        type       = "text", x = 0, y = 20, width = 24, height = 1
        properties = { markdown = "## C. Retrieval" }
      },
      {
        type = "metric", x = 0, y = 21, width = 12, height = 6
        properties = {
          title  = "rag.retrieval.duration by outcome (avg, seconds)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.retrieval.duration", "operation", "search", "outcome", "hit", { label = "hit (avg, seconds)" }],
            [local.observability_namespace, "rag.retrieval.duration", "operation", "search", "outcome", "empty", { label = "empty (avg, seconds)" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 21, width = 12, height = 6
        properties = {
          title  = "rag.retrieval.results by outcome (avg, count)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.retrieval.results", "operation", "search", "outcome", "hit", { label = "hit (avg)" }],
            [local.observability_namespace, "rag.retrieval.results", "operation", "search", "outcome", "empty", { label = "empty (avg)" }],
          ]
        }
      },

      # --- D. GenAI --------------------------------------------------------------
      {
        type       = "text", x = 0, y = 27, width = 24, height = 1
        properties = { markdown = "## D. GenAI" }
      },
      {
        type = "metric", x = 0, y = 28, width = 12, height = 6
        properties = {
          title  = "gen_ai.client.operation.duration (avg, seconds)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "gen_ai.client.operation.duration", "model", "us.anthropic.claude-sonnet-4-6", "operation", "chat", "outcome", "success", { label = "chat (claude-sonnet-4-6, avg, seconds)" }],
            [local.observability_namespace, "gen_ai.client.operation.duration", "model", "amazon.titan-embed-text-v2:0", "operation", "embeddings", "outcome", "success", { label = "embeddings (titan-embed-text-v2, avg, seconds)" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 28, width = 12, height = 6
        properties = {
          title  = "gen_ai.client.token.usage by token type (avg)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "gen_ai.client.token.usage", "token.type", "input", "model", "us.anthropic.claude-sonnet-4-6", "operation", "chat", { label = "input tokens (avg)" }],
            [local.observability_namespace, "gen_ai.client.token.usage", "token.type", "output", "model", "us.anthropic.claude-sonnet-4-6", "operation", "chat", { label = "output tokens (avg)" }],
          ]
        }
      },

      # --- E. Database -----------------------------------------------------------
      {
        type       = "text", x = 0, y = 34, width = 24, height = 1
        properties = { markdown = "## E. Database" }
      },
      {
        type = "metric", x = 0, y = 35, width = 24, height = 6
        properties = {
          title  = "db.client.operation.duration by operation (avg, seconds)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "db.client.operation.duration", "operation", "upsert", "outcome", "success", { label = "upsert (avg, seconds)" }],
            [local.observability_namespace, "db.client.operation.duration", "operation", "search", "outcome", "success", { label = "search (avg, seconds)" }],
          ]
        }
      },

      # --- F. Ingestion ----------------------------------------------------------
      {
        type       = "text", x = 0, y = 41, width = 24, height = 1
        properties = { markdown = "## F. Ingestion" }
      },
      {
        type = "metric", x = 0, y = 42, width = 12, height = 6
        properties = {
          title  = "rag.ingest.duration (avg, seconds)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.ingest.duration", "classification", "internal", "outcome", "success", { label = "internal (avg, seconds)" }],
          ]
        }
      },
      {
        type = "metric", x = 12, y = 42, width = 12, height = 6
        properties = {
          title  = "rag.ingest.chunks (avg, count)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.ingest.chunks", "classification", "internal", "outcome", "success", { label = "internal (avg)" }],
          ]
        }
      },

      # --- G. Security -------------------------------------------------------------
      {
        type       = "text", x = 0, y = 48, width = 24, height = 1
        properties = { markdown = "## G. Security" }
      },
      {
        type = "metric", x = 0, y = 49, width = 16, height = 6
        properties = {
          title  = "rag.security.events by event (sum) — bounded [event] dimension"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.security.events", "event", "missing_tenant"],
            [local.observability_namespace, "rag.security.events", "event", "unknown_tenant"],
            [local.observability_namespace, "rag.security.events", "event", "unknown_role"],
            [local.observability_namespace, "rag.security.events", "event", "action_denied"],
            [local.observability_namespace, "rag.security.events", "event", "classification_denied"],
            [local.observability_namespace, "rag.security.events", "event", "path_rejected"],
            [local.observability_namespace, "rag.security.events", "event", "prompt_too_large"],
            [local.observability_namespace, "rag.security.events", "event", "input_sanitized"],
            [local.observability_namespace, "rag.security.events", "event", "rls_violation"],
          ]
        }
      },
      {
        type = "metric", x = 16, y = 49, width = 8, height = 6
        properties = {
          title  = "rag.security.events — bounded [event, role] breakdown (sum)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 300
          metrics = [
            [local.observability_namespace, "rag.security.events", "event", "action_denied", "role", "reader", { label = "action_denied / reader" }],
            [local.observability_namespace, "rag.security.events", "event", "classification_denied", "role", "ingestor", { label = "classification_denied / ingestor" }],
            [local.observability_namespace, "rag.security.events", "event", "path_rejected", "role", "admin", { label = "path_rejected / admin" }],
            [local.observability_namespace, "rag.security.events", "event", "prompt_too_large", "role", "reader", { label = "prompt_too_large / reader" }],
            [local.observability_namespace, "rag.security.events", "event", "rls_violation", "role", "reader", { label = "rls_violation / reader" }],
          ]
        }
      },

      # --- H. HTTP -------------------------------------------------------------------
      {
        type       = "text", x = 0, y = 55, width = 24, height = 1
        properties = { markdown = "## H. HTTP" }
      },
      {
        type = "metric", x = 0, y = 56, width = 24, height = 6
        properties = {
          title  = "http.server.request.duration (avg, seconds)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 300
          metrics = [
            [local.observability_namespace, "http.server.request.duration", "http.request.method", "POST", "http.route", "/v1/query", "http.response.status_code", "200", { label = "POST /v1/query 200 (avg, seconds)" }],
          ]
        }
      },
    ]
  })
}
