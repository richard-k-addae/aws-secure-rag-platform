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

  # Keep superseded revisions registered and register the new one first. The
  # deployment circuit breaker rolls back to the previous revision, so that
  # revision must still exist while a new one is being deployed.
  skip_destroy = true

  lifecycle {
    create_before_destroy = true
  }

  # No volumes. Privileged mode is not available on Fargate, so the flag is left unset.
  # The only secret is DATABASE_URL for the least-privilege rag_app role; ADMIN_DATABASE_URL
  # and the master credentials are never given to this task.
  container_definitions = jsonencode(concat(
    [
      {
        name      = local.container_name
        image     = local.image
        essential = true

        user                   = "app"
        readonlyRootFilesystem = true

        # The empty lists below are the defaults ECS stores. Declaring them keeps
        # the configuration identical to the registered revision, so unrelated
        # applies do not register a new one and redeploy the service.
        linuxParameters = {
          capabilities = {
            add  = []
            drop = ["ALL"]
          }
        }

        mountPoints       = []
        systemControls    = []
        volumesFrom       = []
        cpu               = var.enable_adot_sidecar ? 384 : var.task_cpu
        memoryReservation = 1536

        portMappings = [
          {
            containerPort = var.app_port
            hostPort      = var.app_port
            protocol      = "tcp"
          }
        ]

        dependsOn = var.enable_adot_sidecar ? [
          {
            containerName = "aws-otel-collector"
            condition     = "START"
          }
        ] : []

        environment = concat(
          [
            { name = "APP_ENV", value = var.environment },
            { name = "AWS_REGION", value = local.region },
            { name = "BEDROCK_MODEL_ID", value = var.bedrock_inference_profile_id },
            { name = "EMBEDDING_MODEL_ID", value = var.bedrock_embedding_model_id },
            { name = "LOG_FULL_CONTENT", value = "false" },
          ],
          var.enable_adot_sidecar ? [
            { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = "http://localhost:4318" },
            { name = "OTEL_METRIC_EXPORT_INTERVAL", value = "15000" },
          ] : []
        )

        # One JSON key of the runtime secret, resolved by ECS at task start
        # with the execution role. The value never appears in Terraform.
        secrets = [
          {
            name      = "DATABASE_URL"
            valueFrom = "${var.db_runtime_secret_arn}:DATABASE_URL::"
          },
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
    ],
    var.enable_adot_sidecar ? [
      {
        name      = "aws-otel-collector"
        image     = "${var.adot_ecr_repository_url}@${var.adot_image_digest}"
        essential = true

        user                   = "aoc"
        readonlyRootFilesystem = true

        linuxParameters = {
          capabilities = {
            add  = []
            drop = ["ALL"]
          }
        }

        mountPoints       = []
        systemControls    = []
        volumesFrom       = []
        cpu               = 128
        memory            = 512
        memoryReservation = 256

        portMappings = [
          {
            containerPort = 4318
            hostPort      = 4318
            protocol      = "tcp"
          },
          {
            containerPort = 13133
            hostPort      = 13133
            protocol      = "tcp"
          }
        ]

        environment = [
          { name = "AWS_REGION", value = local.region },
          { name = "AOT_CONFIG_CONTENT", value = var.adot_config_content }
        ]

        healthCheck = {
          command     = ["/healthcheck"]
          interval    = 30
          timeout     = 5
          retries     = 3
          startPeriod = 15
        }

        logConfiguration = {
          logDriver = "awslogs"
          options = {
            "awslogs-group"         = aws_cloudwatch_log_group.app.name
            "awslogs-region"        = local.region
            "awslogs-stream-prefix" = "collector"
          }
        }
      }
    ] : []
  ))

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
