# VPC Flow Logs: all traffic for the platform VPC, delivered to a dedicated
# KMS-encrypted CloudWatch log group through a role used for nothing else.

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  flow_log_group_name = "/aws/vpc/rag-platform-${var.environment}-flow-logs"

  # Built from its parts so the key policy can name the log group without
  # depending on it (the log group itself depends on the key).
  flow_log_group_arn = "arn:aws:logs:${local.region}:${local.account_id}:log-group:${local.flow_log_group_name}"
}

resource "aws_kms_key" "flow_logs" {
  description             = "Encrypts VPC flow logs for rag-platform-${var.environment}"
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
        Sid    = "AllowCloudWatchLogsForFlowLogGroupOnly"
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
            "kms:EncryptionContext:aws:logs:arn" = local.flow_log_group_arn
          }
        }
      },
    ]
  })

  tags = {
    Name = "rag-platform-${var.environment}-vpc-flow-logs-key"
  }
}

resource "aws_kms_alias" "flow_logs" {
  name          = "alias/rag-platform-${var.environment}-vpc-flow-logs"
  target_key_id = aws_kms_key.flow_logs.key_id
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = local.flow_log_group_name
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = aws_kms_key.flow_logs.arn

  tags = {
    Name = "rag-platform-${var.environment}-vpc-flow-logs"
  }
}

resource "aws_iam_role" "flow_logs" {
  name = "rag-platform-${var.environment}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowVpcFlowLogsService"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:ec2:${local.region}:${local.account_id}:vpc-flow-log/*"
          }
        }
      },
    ]
  })

  tags = {
    Name = "rag-platform-${var.environment}-vpc-flow-logs-role"
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "rag-platform-${var.environment}-vpc-flow-logs-delivery"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # No logs:CreateLogGroup: the log group is created above.
        Sid    = "DeliverToFlowLogGroupOnly"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
        ]
        Resource = [
          aws_cloudwatch_log_group.flow_logs.arn,
          "${aws_cloudwatch_log_group.flow_logs.arn}:*",
        ]
      },
      {
        # Usable only through CloudWatch Logs, and only on the flow-log key.
        Sid    = "UseFlowLogKeyViaCloudWatchLogsOnly"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:ReEncrypt*",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = aws_kms_key.flow_logs.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "logs.${local.region}.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 600

  tags = {
    Name = "rag-platform-${var.environment}-vpc-flow-log"
  }

  depends_on = [aws_iam_role_policy.flow_logs]
}
