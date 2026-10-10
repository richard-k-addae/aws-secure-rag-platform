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

module "ecr" {
  source          = "../../modules/ecr"
  repository_name = "aws-secure-rag-platform"
}

module "security" {
  source                 = "../../modules/security"
  environment            = var.environment
  vpc_id                 = module.networking.vpc_id
  private_subnet_ids     = module.networking.private_subnet_ids
  private_route_table_id = module.networking.private_route_table_id

  ecr_repository_arn                = module.ecr.repository_arn
  bedrock_inference_profile_id      = var.bedrock_inference_profile_id
  bedrock_generation_model_id       = var.bedrock_generation_model_id
  bedrock_inference_profile_regions = var.bedrock_inference_profile_regions
  bedrock_embedding_model_id        = var.bedrock_embedding_model_id
}
