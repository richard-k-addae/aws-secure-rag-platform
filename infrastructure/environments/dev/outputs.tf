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
