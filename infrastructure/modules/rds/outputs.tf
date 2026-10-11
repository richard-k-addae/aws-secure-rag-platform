output "endpoint_address" {
  description = "Hostname of the PostgreSQL instance (resolvable only inside the VPC)"
  value       = aws_db_instance.this.address
}

output "port" {
  description = "PostgreSQL port"
  value       = aws_db_instance.this.port
}

output "db_name" {
  description = "Name of the application database"
  value       = aws_db_instance.this.db_name
}

output "security_group_id" {
  description = "ID of the database security group"
  value       = aws_security_group.rds.id
}

output "kms_key_arn" {
  description = "ARN of the database KMS key"
  value       = aws_kms_key.rds.arn
}

# The ARN only. The secret value is never read by Terraform.
output "master_user_secret_arn" {
  description = "ARN of the RDS-managed master credential secret (bootstrap and migrations only)"
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

# The ARN only. Terraform never creates or reads a version of this secret.
output "runtime_secret_arn" {
  description = "ARN of the empty secret that will hold the rag_app runtime DATABASE_URL"
  value       = aws_secretsmanager_secret.runtime.arn
}
