variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC the security groups and endpoints belong to"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs that host the interface endpoints"
  type        = list(string)
}

variable "private_route_table_id" {
  description = "Private route table that receives the S3 gateway endpoint route"
  type        = string
}

variable "ecr_repository_arn" {
  description = "ARN of the ECR repository that tasks may pull from through the ECR endpoints"
  type        = string
}

variable "bedrock_inference_profile_id" {
  description = "ID of the Bedrock inference profile used for generation"
  type        = string
}

variable "bedrock_generation_model_id" {
  description = "Foundation model ID behind the generation inference profile"
  type        = string
}

variable "bedrock_inference_profile_regions" {
  description = "Regions the generation inference profile can route to"
  type        = list(string)
}

variable "bedrock_embedding_model_id" {
  description = "Foundation model ID used for embeddings"
  type        = string
}

variable "app_port" {
  description = "Port the application container listens on"
  type        = number
  default     = 8000
}
