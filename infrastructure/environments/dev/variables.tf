variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.20.0.0/16"
}

variable "bedrock_inference_profile_id" {
  description = "ID of the Bedrock inference profile used for generation"
  type        = string
  default     = "us.anthropic.claude-sonnet-4-6"
}

variable "bedrock_generation_model_id" {
  description = "Foundation model ID behind the generation inference profile"
  type        = string
  default     = "anthropic.claude-sonnet-4-6"
}

variable "bedrock_inference_profile_regions" {
  description = "Regions the generation inference profile can route to"
  type        = list(string)
  default     = ["us-east-1", "us-east-2", "us-west-2"]
}

variable "bedrock_embedding_model_id" {
  description = "Foundation model ID used for embeddings"
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

variable "app_image_digest" {
  description = "Digest of the signed release candidate image deployed to ECS (commit 1194012)"
  type        = string
  default     = "sha256:05c5ef1b3f3350804f57680c996737c896e31fe39394de6008d16dfe5d7d6a44"
}

variable "db_bootstrap_image_digest" {
  description = "Digest of the signed image used by the database bootstrap task (commit 1194012)"
  type        = string
  default     = "sha256:05c5ef1b3f3350804f57680c996737c896e31fe39394de6008d16dfe5d7d6a44"
}

variable "adot_image_digest" {
  description = "Immutable digest of the project-built patched AWS Distro for OpenTelemetry collector image (v0.50.0-patched.1 linux/amd64)"
  type        = string
  default     = "sha256:429737a8f281d09b7bc8b00af0bfe4778ffc31b04be2ba9abdb1aec9147600f7"

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.adot_image_digest))
    error_message = "adot_image_digest must be a full sha256 digest (sha256:<64 hex characters>), not a tag."
  }
}
