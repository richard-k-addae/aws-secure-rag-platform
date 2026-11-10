# M8.5 identity-eval bootstrap: the two temporary IAM roles that the M8.5
# Terraform wrapper (rag-eval-terraform) and the live Cognito harness
# (rag-eval-harness) run as.
#
# Isolation: separate root and LOCAL state (never the shared dev state bucket).
# Creates only two IAM roles and their two inline policies. No data sources over
# existing infrastructure, no modules, no imports, no references to dev IAM,
# ECS, RDS, VPC or Secrets Manager. Destroy after M8.5 (see README.md).
terraform {
  required_version = ">= 1.10"

  # Explicitly local and gitignored (*.tfstate*). Holds role ARNs and policy JSON
  # only: no credentials.
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

# No credential, profile, endpoint or assume_role settings: the operator supplies
# credentials through the environment for the one-time bootstrap apply.
provider "aws" {
  region = var.aws_region
  # Hard guard: plan/apply fail if credentials resolve to any other account.
  allowed_account_ids = [var.expected_account_id]

  default_tags {
    tags = {
      Project     = "aws-secure-rag-platform"
      Environment = "identity-eval-bootstrap"
      Milestone   = "M8.5"
      ManagedBy   = "Terraform"
      Ephemeral   = "true"
      ExpiresOn   = var.expires_on
    }
  }
}
