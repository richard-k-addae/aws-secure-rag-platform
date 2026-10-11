variable "environment" {
  description = "Environment name"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs the tasks run in"
  type        = list(string)
}

variable "ecs_security_group_id" {
  description = "ID of the existing ECS task security group"
  type        = string
}

variable "ecr_repository_arn" {
  description = "ARN of the ECR repository the execution role may pull from"
  type        = string
}

variable "ecr_repository_url" {
  description = "URL of the ECR repository that holds the application image"
  type        = string
}

variable "image_digest" {
  description = "Immutable sha256 digest of the reviewed application image"
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be a full sha256 digest (sha256:<64 hex characters>), not a tag."
  }
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

variable "task_cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "Fargate task memory in MiB"
  type        = number
  default     = 1024
}

variable "desired_count" {
  description = "Number of tasks the service keeps running"
  type        = number
  default     = 1
}

variable "log_retention_days" {
  description = "Retention of the application log group in days"
  type        = number
  default     = 365
}

variable "db_bootstrap_image_digest" {
  description = "Immutable sha256 digest of the signed image used by the one-shot database bootstrap task"
  type        = string

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.db_bootstrap_image_digest))
    error_message = "db_bootstrap_image_digest must be a full sha256 digest (sha256:<64 hex characters>), not a tag."
  }
}

variable "db_host" {
  description = "Hostname of the PostgreSQL instance"
  type        = string
}

variable "db_port" {
  description = "PostgreSQL port"
  type        = number
}

variable "db_name" {
  description = "Name of the application database"
  type        = string
}

variable "db_app_role" {
  description = "Name of the least-privilege runtime database role"
  type        = string
  default     = "rag_app"
}

variable "embedding_dimensions" {
  description = "Dimension of the embedding column, matching the embedding model"
  type        = number
  default     = 1024
}

variable "db_master_secret_arn" {
  description = "ARN of the RDS-managed master secret. Readable by the bootstrap task role only"
  type        = string
}

variable "db_runtime_secret_arn" {
  description = "ARN of the rag_app runtime secret"
  type        = string
}

variable "db_kms_key_arn" {
  description = "ARN of the KMS key that encrypts both database secrets"
  type        = string
}
