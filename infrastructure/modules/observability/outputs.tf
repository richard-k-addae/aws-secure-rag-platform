output "metrics_log_group_name" {
  description = "Name of the dedicated CloudWatch log group for ADOT EMF metrics"
  value       = aws_cloudwatch_log_group.metrics.name
}

output "metrics_log_group_arn" {
  description = "ARN of the dedicated CloudWatch log group for ADOT EMF metrics"
  value       = aws_cloudwatch_log_group.metrics.arn
}

output "metrics_kms_key_arn" {
  description = "ARN of the KMS key encrypting the metrics log group"
  value       = aws_kms_key.metrics_logs.arn
}

output "adot_collector_config" {
  description = "Rendered OpenTelemetry Collector configuration for ADOT in-memory injection via AOT_CONFIG_CONTENT"
  value = templatefile("${path.module}/templates/adot-collector-config.yaml.tpl", {
    aws_region     = local.region
    log_group_name = aws_cloudwatch_log_group.metrics.name
    namespace      = var.namespace
  })
}
