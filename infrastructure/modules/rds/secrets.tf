# Container for the application's runtime database credential (the rag_app
# role). Terraform creates the secret but never a version of it, so no
# password is ever in Terraform state or outputs. The value is written later
# by a controlled operator step as a single DATABASE_URL for rag_app, using
# sslmode=verify-full and the RDS CA bundle shipped in the image. It never
# holds the master password, which lives in the separate RDS-managed secret.
resource "aws_secretsmanager_secret" "runtime" {
  # checkov:skip=CKV2_AWS_57: Runtime DB credential rotation requires a coordinated password change in PostgreSQL and Secrets Manager. Automatic rotation infrastructure is deferred until after initial M5 database bootstrap/connectivity validation. Secret is least-privilege rag_app only; master credentials are separate and AWS-managed. Review by 2026-11-09.
  name                    = "${local.name}/db/rag-app-runtime"
  description             = "Runtime DATABASE_URL for the rag_app role (NOSUPERUSER, NOBYPASSRLS). Not the master credential."
  kms_key_id              = aws_kms_key.rds.arn
  recovery_window_in_days = 30

  tags = {
    Name = "${local.name}-db-rag-app-runtime"
  }
}
