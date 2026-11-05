# Application logs: a dedicated KMS key and log group, separate from the VPC
# flow-log key so each key is tied to exactly one log group.

locals {
  app_log_group_name = "/aws/ecs/${local.name}"

  # Built from its parts so the key policy can name the log group without
  # depending on it (the log group itself depends on the key).
  app_log_group_arn = "arn:aws:logs:${local.region}:${local.account_id}:log-group:${local.app_log_group_name}"
}

resource "aws_kms_key" "app_logs" {
  description             = "Encrypts ECS application logs for ${local.name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Grants nothing by itself: it lets IAM policies in this account
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
        Sid    = "AllowCloudWatchLogsForAppLogGroupOnly"
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
            "kms:EncryptionContext:aws:logs:arn" = local.app_log_group_arn
          }
        }
      },
    ]
  })

  tags = {
    Name = "${local.name}-ecs-logs-key"
  }
}

resource "aws_kms_alias" "app_logs" {
  name          = "alias/${local.name}-ecs-logs"
  target_key_id = aws_kms_key.app_logs.key_id
}

resource "aws_cloudwatch_log_group" "app" {
  name              = local.app_log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.app_logs.arn

  tags = {
    Name = "${local.name}-ecs-logs"
  }
}
