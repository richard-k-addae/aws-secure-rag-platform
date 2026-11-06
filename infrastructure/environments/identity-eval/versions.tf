# M8.5 identity-eval: temporary, isolated Cognito user pool for validating the
# production JWT verifier against real Cognito-issued tokens.
#
# Isolation: separate root and LOCAL state (never the shared dev state bucket),
# no VPC/ECS/RDS/IAM resources, no data sources over existing infrastructure.
# Destroy after evidence capture.
terraform {
  required_version = ">= 1.10"

  # Explicitly local and gitignored (*.tfstate*). Holds identifiers only: no
  # users or passwords are managed here (see scripts/validate_live_cognito.py).
  backend "local" {
    path = "terraform.tfstate"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  # Hard guard: plan/apply fail if credentials resolve to any other account.
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = {
      Project     = "aws-secure-rag-platform"
      Environment = "identity-eval"
      Milestone   = "M8.5"
      ManagedBy   = "terraform"
      Ephemeral   = "true"
      ExpiresOn   = var.expires_on
    }
  }
}
