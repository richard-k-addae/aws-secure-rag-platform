variable "repository_name" {
  description = "Name of the ECR repository"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "kms_alias_name" {
  description = "Optional custom KMS alias name for the repository encryption key"
  type        = string
  default     = null
}
