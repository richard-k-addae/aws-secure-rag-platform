# M6.5B: CloudWatch alarms for the secure RAG platform.
# All alarms are state-only (actions_enabled = false) — no SNS destination is
# approved yet. Only the 4 alarms explicitly authorized for this phase are
# implemented; latency/no-context-rate/token-anomaly/telemetry-silence alarms
# require baseline evidence or a heartbeat signal and are intentionally
# deferred (see infrastructure/modules/observability/README.md).

# --- A. RLS violation (DETERMINISTIC) ----------------------------------------
resource "aws_cloudwatch_metric_alarm" "security_rls_violation" {
  # checkov:skip=CKV_AWS_319: No SNS notification destination is approved yet (M6.5B). Alarm remains state-only (actions_enabled = false) by explicit design until a destination is reviewed and attached. Review by 2026-11-09.
  alarm_name          = "rag-platform-${var.environment}-security-rls-violation"
  alarm_description   = "Fires when rag.security.events records a row-level-security violation (event=rls_violation). Deterministic: any occurrence is a confirmed security signal, not a threshold judgment."
  namespace           = local.observability_namespace
  metric_name         = "rag.security.events"
  dimensions          = { event = "rls_violation" }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  actions_enabled           = false
  alarm_actions             = []
  ok_actions                = []
  insufficient_data_actions = []
}

# --- B. Running task deficit (INFRASTRUCTURE SAFETY) -------------------------
resource "aws_cloudwatch_metric_alarm" "ecs_running_task_deficit" {
  # checkov:skip=CKV_AWS_319: No SNS notification destination is approved yet (M6.5B). Alarm remains state-only (actions_enabled = false) by explicit design until a destination is reviewed and attached. Review by 2026-11-09.
  alarm_name          = "rag-platform-${var.environment}-running-task-deficit"
  alarm_description   = "Fires when RunningTaskCount falls below DesiredTaskCount. Uses metric math so a deliberate scale-to-zero (DesiredTaskCount = 0) never alarms."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"

  actions_enabled           = false
  alarm_actions             = []
  ok_actions                = []
  insufficient_data_actions = []

  metric_query {
    id          = "running"
    return_data = false
    metric {
      namespace   = "ECS/ContainerInsights"
      metric_name = "RunningTaskCount"
      dimensions  = { ClusterName = local.observability_cluster, ServiceName = local.observability_service }
      period      = 60
      stat        = "Average"
    }
  }

  metric_query {
    id          = "desired"
    return_data = false
    metric {
      namespace   = "ECS/ContainerInsights"
      metric_name = "DesiredTaskCount"
      dimensions  = { ClusterName = local.observability_cluster, ServiceName = local.observability_service }
      period      = 60
      stat        = "Average"
    }
  }

  metric_query {
    id          = "deficit"
    label       = "Task deficit (desired - running, floored at 0 when desired = 0)"
    expression  = "IF(desired > 0, desired - running, 0)"
    return_data = true
  }
}

# --- C. CPU high (PROVISIONAL) ------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "ecs_cpu_high" {
  # checkov:skip=CKV_AWS_319: No SNS notification destination is approved yet (M6.5B). Alarm remains state-only (actions_enabled = false) by explicit design until a destination is reviewed and attached. Review by 2026-11-09.
  alarm_name          = "rag-platform-${var.environment}-cpu-high"
  alarm_description   = "Provisional threshold pending baseline."
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  dimensions          = { ClusterName = local.observability_cluster, ServiceName = local.observability_service }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 80
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "missing"

  actions_enabled           = false
  alarm_actions             = []
  ok_actions                = []
  insufficient_data_actions = []
}

# --- D. Memory high (PROVISIONAL) --------------------------------------------
resource "aws_cloudwatch_metric_alarm" "ecs_memory_high" {
  # checkov:skip=CKV_AWS_319: No SNS notification destination is approved yet (M6.5B). Alarm remains state-only (actions_enabled = false) by explicit design until a destination is reviewed and attached. Review by 2026-11-09.
  alarm_name          = "rag-platform-${var.environment}-memory-high"
  alarm_description   = "Provisional threshold pending baseline."
  namespace           = "AWS/ECS"
  metric_name         = "MemoryUtilization"
  dimensions          = { ClusterName = local.observability_cluster, ServiceName = local.observability_service }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  datapoints_to_alarm = 3
  threshold           = 80
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "missing"

  actions_enabled           = false
  alarm_actions             = []
  ok_actions                = []
  insufficient_data_actions = []
}
