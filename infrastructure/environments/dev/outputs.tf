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
