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
  description = "Digest of the signed release candidate image deployed to ECS (commit 2b28877)"
  type        = string
  default     = "sha256:ad84796c69fb4f480b89fe8e6b9081c3c0755ab9f248e2e4a4b24d08d8d7340a"
}
