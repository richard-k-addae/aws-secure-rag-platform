# Observability module: dedicated KMS key and CloudWatch log group for ADOT EMF
# metrics, plus the rendered ADOT collector in-memory configuration.
#
# Metrics are delivered to CloudWatch Logs as Embedded Metric Format (EMF) payloads
# via the existing private logs VPC endpoint. CloudWatch automatically extracts
# metrics into the configured namespace without requiring any monitoring VPC endpoint.

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  name       = "rag-platform-${var.environment}"

  metrics_log_group_name = "/aws/ecs/${local.name}/metrics"

  # Built from its parts so the key policy can name the log group without
  # depending on it (the log group itself depends on the key).
  metrics_log_group_arn = "arn:aws:logs:${local.region}:${local.account_id}:log-group:${local.metrics_log_group_name}"
}

# Dedicated KMS key for EMF metrics log group.
# Following the project standard of 1-to-1 key to log group mapping with encryption context.
resource "aws_kms_key" "metrics_logs" {
  description             = "Encrypts CloudWatch EMF metrics logs for ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Grants nothing by itself: lets IAM policies in this account
        # authorize use of the key and keeps the key administrable.
        Sid    = "EnableIamPolicies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsForMetricsLogGroupOnly"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = local.metrics_log_group_arn
          }
        }
      },
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${local.name}-metrics-logs-key"
    }
  )
}

resource "aws_kms_alias" "metrics_logs" {
  name          = "alias/${local.name}-metrics-logs"
  target_key_id = aws_kms_key.metrics_logs.key_id
}

resource "aws_cloudwatch_log_group" "metrics" {
  name              = local.metrics_log_group_name
  retention_in_days = var.retention_in_days
  kms_key_id        = aws_kms_key.metrics_logs.arn

  tags = merge(
    var.tags,
    {
      Name = "${local.name}-metrics-logs"
    }
  )
}
