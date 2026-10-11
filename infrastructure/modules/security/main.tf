# Security module: security groups for the ALB, ECS tasks and interface
# endpoints, plus the VPC endpoints that keep AWS service traffic private.

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.name}.s3"
}

locals {
  interface_endpoint_services = toset([
    "ecr.api",
    "ecr.dkr",
    "logs",
    "bedrock-runtime",
    "secretsmanager",
  ])

  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Endpoint policies cap what any caller in the VPC can do through an
  # endpoint. They do not grant access: IAM roles still need their own allows.
  same_account_only = {
    StringEquals = {
      "aws:PrincipalAccount" = local.account_id
    }
  }

  # AWS recommends one pull policy attached to both ECR endpoints.
  # GetAuthorizationToken does not support resource-level scoping.
  ecr_pull_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowRegistryAuth"
        Effect    = "Allow"
        Principal = "*"
        Action    = "ecr:GetAuthorizationToken"
        Resource  = "*"
        Condition = local.same_account_only
      },
      {
        Sid       = "AllowImagePull"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource  = var.ecr_repository_arn
        Condition = local.same_account_only
      },
    ]
  })

  # Sufficient for the awslogs driver when the log group is pre-created.
  logs_delivery_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowLogDelivery"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource  = "arn:aws:logs:${local.region}:${local.account_id}:log-group:*"
        Condition = local.same_account_only
      },
    ]
  })

  # Converse is authorized as bedrock:InvokeModel; there is no separate action.
  # A cross-region inference profile also authorizes against the foundation
  # model in every region it routes to.
  bedrock_runtime_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowApprovedModelInvocation"
        Effect    = "Allow"
        Principal = "*"
        Action    = "bedrock:InvokeModel"
        Resource = concat(
          ["arn:aws:bedrock:${local.region}:${local.account_id}:inference-profile/${var.bedrock_inference_profile_id}"],
          [for r in var.bedrock_inference_profile_regions : "arn:aws:bedrock:${r}::foundation-model/${var.bedrock_generation_model_id}"],
          ["arn:aws:bedrock:${local.region}::foundation-model/${var.bedrock_embedding_model_id}"],
        )
        Condition = local.same_account_only
      },
    ]
  })

  secretsmanager_read_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowSecretRetrieval"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
        ]
        Resource  = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:*"
        Condition = local.same_account_only
      },
    ]
  })

  interface_endpoint_policies = {
    "ecr.api"         = local.ecr_pull_policy
    "ecr.dkr"         = local.ecr_pull_policy
    "logs"            = local.logs_delivery_policy
    "bedrock-runtime" = local.bedrock_runtime_policy
    "secretsmanager"  = local.secretsmanager_read_policy
  }

  # ECR stores image layers in this AWS-owned bucket. No account condition:
  # the bucket is not ours, and AWS documents this policy with Principal "*".
  s3_gateway_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEcrLayerDownload"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::prod-${local.region}-starport-layer-bucket/*"
      },
    ]
  })
}

resource "aws_security_group" "alb" {
  # checkov:skip=CKV2_AWS_5: Reserved for the later controlled ALB/TLS phase; currently has no public ingress and intentionally has no attached resource. Review by 2026-11-09.
  name        = "rag-platform-${var.environment}-alb-sg"
  description = "Security group for the application load balancer"
  vpc_id      = var.vpc_id

  tags = {
    Name = "rag-platform-${var.environment}-alb-sg"
  }
}

resource "aws_security_group" "ecs" {
  # checkov:skip=CKV2_AWS_5: Attached to aws_ecs_service in the ECS child module via module output/input; Checkov CKV2_AWS_5 cannot resolve the cross-module attachment. Review by 2026-11-09.
  name        = "rag-platform-${var.environment}-ecs-sg"
  description = "Security group for ECS Fargate tasks"
  vpc_id      = var.vpc_id

  tags = {
    Name = "rag-platform-${var.environment}-ecs-sg"
  }
}

resource "aws_security_group" "endpoints" {
  name        = "rag-platform-${var.environment}-endpoints-sg"
  description = "Security group for interface VPC endpoints"
  vpc_id      = var.vpc_id

  tags = {
    Name = "rag-platform-${var.environment}-endpoints-sg"
  }
}

resource "aws_vpc_security_group_egress_rule" "alb_to_ecs" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Application traffic to ECS tasks only"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.ecs.id
}

resource "aws_vpc_security_group_ingress_rule" "ecs_from_alb" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Application traffic from ALB only"
  ip_protocol                  = "tcp"
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "ecs_to_endpoints" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "HTTPS to private AWS service endpoints"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.endpoints.id
}

resource "aws_vpc_security_group_egress_rule" "ecs_to_s3" {
  security_group_id = aws_security_group.ecs.id
  description       = "HTTPS to S3 through gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = data.aws_prefix_list.s3.id
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_ecs" {
  security_group_id            = aws_security_group.endpoints.id
  description                  = "HTTPS from ECS tasks only"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.ecs.id
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_services

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy              = local.interface_endpoint_policies[each.key]

  tags = {
    Name = "rag-platform-${var.environment}-${replace(each.key, ".", "-")}-endpoint"
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [var.private_route_table_id]
  policy            = local.s3_gateway_policy

  tags = {
    Name = "rag-platform-${var.environment}-s3-endpoint"
  }
}
