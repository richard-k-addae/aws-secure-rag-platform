# Container for the application's runtime database credential (the rag_app
# role). Terraform creates the secret but never a version of it, so no
# password is ever in Terraform state or outputs. The value is written later
# by a controlled operator step as a single DATABASE_URL for rag_app, using
# sslmode=verify-full and the RDS CA bundle shipped in the image. It never
# holds the master password, which lives in the separate RDS-managed secret.
resource "aws_secretsmanager_secret" "runtime" {
  # checkov:skip=CKV2_AWS_57: Risk acceptance, not a mitigation. Automatic rotation is not implemented: safe rotation needs coordinated PostgreSQL credential changes, Secrets Manager rotation behavior and application/runtime validation, which would expand the closed project scope. Production-readiness residual risk. Secret holds the least-privilege rag_app credential only; master credentials are separate and AWS-managed. Renewed 2026-11-10; review by 2027-02-04.
  name                    = "${local.name}/db/rag-app-runtime"
  description             = "Runtime DATABASE_URL for the rag_app role (NOSUPERUSER, NOBYPASSRLS). Not the master credential."
  kms_key_id              = aws_kms_key.rds.arn
  recovery_window_in_days = 30

  tags = {
    Name = "${local.name}-db-rag-app-runtime"
  }
}
