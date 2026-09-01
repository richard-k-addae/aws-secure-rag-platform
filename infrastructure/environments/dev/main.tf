module "networking" {
  source      = "../../modules/networking"
  environment = var.environment
  vpc_cidr    = var.vpc_cidr
}

# Phase 2:
# module "rds"       { source = "../../modules/rds" ... }
# module "ecs"       { source = "../../modules/ecs" ... }
# module "cognito"   { source = "../../modules/cognito" ... }
# module "storage"   { source = "../../modules/storage" ... }
# module "messaging" { source = "../../modules/messaging" ... }
# module "security"  { source = "../../modules/security" ... }

module "ecr" {
  source          = "../../modules/ecr"
  repository_name = "aws-secure-rag-platform"
}