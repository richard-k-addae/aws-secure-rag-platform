# Log groups for the instance's exported logs, created ahead of the instance
# so they are KMS-encrypted and have finite retention, plus the role RDS uses
# to publish enhanced monitoring metrics.

resource "aws_cloudwatch_log_group" "rds" {
  for_each = toset(["postgresql", "upgrade"])

  name              = "/aws/rds/instance/${local.identifier}/${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.rds.arn

  tags = {
    Name = "${local.identifier}-${each.key}-logs"
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name = "${local.name}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRdsEnhancedMonitoring"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
        }
      },
    ]
  })

  tags = {
    Name = "${local.name}-rds-monitoring-role"
  }
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
