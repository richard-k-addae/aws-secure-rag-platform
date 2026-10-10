# Security module: security groups for the ALB, ECS tasks and interface
# endpoints, plus the VPC endpoints that keep AWS service traffic private.

data "aws_region" "current" {}

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
}

resource "aws_security_group" "alb" {
  name        = "rag-platform-${var.environment}-alb-sg"
  description = "Security group for the application load balancer"
  vpc_id      = var.vpc_id

  tags = {
    Name = "rag-platform-${var.environment}-alb-sg"
  }
}

resource "aws_security_group" "ecs" {
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

  tags = {
    Name = "rag-platform-${var.environment}-${replace(each.key, ".", "-")}-endpoint"
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [var.private_route_table_id]

  tags = {
    Name = "rag-platform-${var.environment}-s3-endpoint"
  }
}
