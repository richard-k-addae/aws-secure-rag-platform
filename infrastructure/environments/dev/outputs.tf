output "vpc_id" {
  description = "ID of the platform VPC"
  value       = module.networking.vpc_id
}

output "ecr_repository_url" {
  description = "ECR repository URL for the application image"
  value       = module.ecr.repository_url
}