output "vpc_id" {
  description = "ID of the platform VPC"
  value       = module.networking.vpc_id
}

output "ecr_repository_url" {
  description = "ECR repository URL for the application image"
  value       = module.ecr.repository_url
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.networking.public_subnet_ids
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = module.networking.private_subnet_ids
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = module.ecs.cluster_name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = module.ecs.service_name
}

output "app_log_group_name" {
  description = "Name of the application log group"
  value       = module.ecs.log_group_name
}

output "db_endpoint_address" {
  description = "Hostname of the PostgreSQL instance (resolvable only inside the VPC)"
  value       = module.rds.endpoint_address
}

# The ARN only. The secret value is never read by Terraform.
output "db_master_user_secret_arn" {
  description = "ARN of the RDS-managed master credential secret (bootstrap and migrations only)"
  value       = module.rds.master_user_secret_arn
}

# The ARN only. Terraform never creates or reads a version of this secret.
output "db_runtime_secret_arn" {
  description = "ARN of the empty secret that will hold the rag_app runtime DATABASE_URL"
  value       = module.rds.runtime_secret_arn
}

output "db_bootstrap_task_definition_arn" {
  description = "ARN of the one-shot database bootstrap task definition revision"
  value       = module.ecs.db_bootstrap_task_definition_arn
}

output "adot_ecr_repository_url" {
  description = "ECR repository URL for the mirrored ADOT collector image"
  value       = module.ecr_adot.repository_url
}

output "metrics_log_group_name" {
  description = "Name of the CloudWatch log group receiving ADOT EMF metrics"
  value       = module.observability.metrics_log_group_name
}

output "metrics_log_group_arn" {
  description = "ARN of the CloudWatch log group receiving ADOT EMF metrics"
  value       = module.observability.metrics_log_group_arn
}
