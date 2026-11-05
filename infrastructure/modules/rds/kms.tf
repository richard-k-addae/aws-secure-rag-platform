# Dedicated key for the database: storage, automated backups, the RDS-managed
# master secret, Performance Insights and the instance's exported log groups.

locals {
  # Built from its parts so the key policy can name the log groups without
  # depending on them (the log groups themselves depend on the key).
  rds_log_group_arn_prefix = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/rds/instance/${local.identifier}"
}

resource "aws_kms_key" "rds" {
  description             = "Encrypts the ${local.name} PostgreSQL database, its master secret and its logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Grants nothing by itself: it lets IAM policies in this account
        # authorize use of the key and keeps the key administrable. RDS and
        # Secrets Manager act through grants and the caller's own permissions,
        # so no service or role is named for them.
        Sid    = "EnableIamPolicies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsForRdsLogGroupsOnly"
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
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "${local.rds_log_group_arn_prefix}/*"
          }
        }
      },
    ]
  })

  tags = {
    Name = "${local.name}-rds-key"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}
