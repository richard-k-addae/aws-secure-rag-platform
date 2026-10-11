# RDS PostgreSQL + pgvector module: a private, encrypted instance reachable
# only from the ECS task security group. The KMS key is in kms.tf; log groups
# and the enhanced-monitoring role are in monitoring.tf.
#
# Credentials: RDS generates and rotates the master password in Secrets
# Manager, so no password ever enters Terraform state. The master user is for
# bootstrap and migrations only; the application connects as a separate
# NOSUPERUSER NOBYPASSRLS role created during bootstrap, never as the master.

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  name       = "rag-platform-${var.environment}"
  identifier = "${local.name}-postgres"
}

resource "aws_db_subnet_group" "this" {
  name        = "${local.name}-db-subnets"
  description = "Private subnets for the ${local.name} PostgreSQL instance"
  subnet_ids  = var.private_subnet_ids

  tags = {
    Name = "${local.name}-db-subnets"
  }
}

resource "aws_security_group" "rds" {
  name        = "${local.name}-rds-sg"
  description = "Security group for the PostgreSQL instance"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${local.name}-rds-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "rds_from_ecs" {
  security_group_id            = aws_security_group.rds.id
  description                  = "PostgreSQL from ECS tasks only"
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
  referenced_security_group_id = var.ecs_security_group_id
}

# Lives here, not in the security module, so that module does not have to
# depend on this one. It is the only rule this module adds to the ECS group.
resource "aws_vpc_security_group_egress_rule" "ecs_to_rds" {
  security_group_id            = var.ecs_security_group_id
  description                  = "PostgreSQL to the database only"
  ip_protocol                  = "tcp"
  from_port                    = var.db_port
  to_port                      = var.db_port
  referenced_security_group_id = aws_security_group.rds.id
}

resource "aws_db_parameter_group" "this" {
  name        = "${local.name}-postgres16"
  family      = "postgres16"
  description = "Parameters for the ${local.name} PostgreSQL instance"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }

  # Log schema changes and slow statements, but never bind parameter values:
  # those would carry document content and embeddings into the logs.
  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  parameter {
    name  = "log_parameter_max_length"
    value = "0"
  }

  parameter {
    name  = "log_parameter_max_length_on_error"
    value = "0"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  tags = {
    Name = "${local.name}-postgres16"
  }
}

resource "aws_db_instance" "this" {
  identifier = local.identifier

  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn

  db_name  = var.db_name
  port     = var.db_port
  username = var.master_username

  # RDS owns the master password: generated, stored in Secrets Manager and
  # rotated by AWS. It is never read by Terraform or placed in state.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.rds.key_id

  iam_database_authentication_enabled = true

  multi_az               = var.multi_az
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  parameter_group_name = aws_db_parameter_group.this.name

  backup_retention_period = var.backup_retention_days
  backup_window           = "06:00-07:00"
  maintenance_window      = "sun:07:30-sun:08:30"
  copy_tags_to_snapshot   = true

  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.identifier}-final"

  auto_minor_version_upgrade = true
  apply_immediately          = false

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = aws_kms_key.rds.arn

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  tags = {
    Name = local.identifier
  }

  # The encrypted log groups must exist first, otherwise RDS creates its own
  # unencrypted ones with no retention.
  depends_on = [
    aws_cloudwatch_log_group.rds,
    aws_iam_role_policy_attachment.rds_monitoring,
  ]
}
