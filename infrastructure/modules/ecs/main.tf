# ECS Fargate service module: cluster, hardened task definition and a private,
# headless service. IAM roles are in iam.tf and the KMS-encrypted application
# log group in logging.tf.
#
# There is deliberately no load balancer yet. An ALB needs an approved TLS
# certificate, a deliberate ingress source and access logging, which belong to
# a later phase. Until then the service has no inbound path and its health is
# judged by the container health check alone.

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  name           = "rag-platform-${var.environment}"
  container_name = "app"

  # Deploy the exact reviewed image: digest only, never a mutable tag.
  image = "${var.ecr_repository_url}@${var.image_digest}"
}

resource "aws_ecs_cluster" "this" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = local.name
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = "${local.name}-app"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  # No volumes, no sidecars. Privileged mode is not available on Fargate, so
  # the flag is left unset. ADMIN_DATABASE_URL and DATABASE_URL are
  # deliberately absent: /healthz needs no database.
  container_definitions = jsonencode([
    {
      name      = local.container_name
      image     = local.image
      essential = true

      user                   = "app"
      readonlyRootFilesystem = true

      linuxParameters = {
        capabilities = {
          drop = ["ALL"]
        }
      }

      portMappings = [
        {
          containerPort = var.app_port
          hostPort      = var.app_port
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "APP_ENV", value = var.environment },
        { name = "AWS_REGION", value = local.region },
        { name = "BEDROCK_MODEL_ID", value = var.bedrock_inference_profile_id },
        { name = "EMBEDDING_MODEL_ID", value = var.bedrock_embedding_model_id },
        { name = "LOG_FULL_CONTENT", value = "false" },
      ]

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:${var.app_port}/healthz')\""]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = local.region
          "awslogs-stream-prefix" = local.container_name
        }
      }
    }
  ])

  tags = {
    Name = "${local.name}-app"
  }
}

resource "aws_ecs_service" "app" {
  name             = "${local.name}-app"
  cluster          = aws_ecs_cluster.this.id
  task_definition  = aws_ecs_task_definition.app.arn
  desired_count    = var.desired_count
  launch_type      = "FARGATE"
  platform_version = "LATEST"

  enable_execute_command = false

  # Make apply wait until the task is running and healthy, so a failed first
  # deployment surfaces as a failed apply instead of a silent success.
  wait_for_steady_state = true

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.ecs_security_group_id]
    assign_public_ip = false
  }

  tags = {
    Name = "${local.name}-app"
  }

  # The execution role must be able to pull and log before the first task starts.
  depends_on = [
    aws_iam_role_policy.execution,
  ]
}
