# One-shot database bootstrap task. A standalone task definition with its own
# task role; there is no service for it and it is started by hand.
#
# It is the only workload allowed to read the RDS master secret. The normal
# application roles in iam.tf are untouched and can read neither secret. The
# existing execution role is reused unchanged: it only pulls the image and
# writes logs, because the bootstrap code fetches the secrets itself with the
# task role instead of having ECS inject them.

locals {
  db_bootstrap_name      = "${local.name}-db-bootstrap"
  db_bootstrap_container = "db-bootstrap"

  # Deployed by digest: the signed image that contains the hardened bootstrap
  # code and the RDS CA bundle. Independent of the image the service runs.
  db_bootstrap_image = "${var.ecr_repository_url}@${var.db_bootstrap_image_digest}"

  # Normalised to LF so the registered command is identical whichever
  # platform Terraform runs on.
  db_bootstrap_script = replace(file("${path.module}/files/db_bootstrap.py"), "\r\n", "\n")
}

resource "aws_iam_role" "db_bootstrap" {
  name               = "${local.db_bootstrap_name}-task-role"
  assume_role_policy = local.ecs_tasks_assume_role_policy

  tags = {
    Name = "${local.db_bootstrap_name}-task-role"
  }
}

resource "aws_iam_role_policy" "db_bootstrap" {
  name = "${local.db_bootstrap_name}-secrets"
  role = aws_iam_role.db_bootstrap.id

  # No Bedrock, no RDS management API, no other secret, no other key.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadTheTwoDatabaseSecretsOnly"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = [var.db_master_secret_arn, var.db_runtime_secret_arn]
      },
      {
        # Only to let Secrets Manager decrypt those two secrets.
        Sid      = "DecryptViaSecretsManagerOnly"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.db_kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${local.region}.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_ecs_task_definition" "db_bootstrap" {
  family                   = local.db_bootstrap_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.db_bootstrap.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  # No volumes, no sidecars, no injected secrets. Privileged mode is not
  # available on Fargate. Every environment value below is a non-secret
  # locator; credentials are fetched at run time and never leave memory.
  container_definitions = jsonencode([
    {
      name      = local.db_bootstrap_container
      image     = local.db_bootstrap_image
      essential = true

      command = ["python", "-c", local.db_bootstrap_script]

      user                   = "app"
      readonlyRootFilesystem = true

      # Empty lists are the defaults ECS stores; declaring them avoids a
      # permanent Terraform diff.
      linuxParameters = {
        capabilities = {
          add  = []
          drop = ["ALL"]
        }
      }

      mountPoints    = []
      portMappings   = []
      systemControls = []
      volumesFrom    = []

      environment = [
        { name = "APP_DB_ROLE", value = var.db_app_role },
        { name = "AWS_REGION", value = local.region },
        { name = "DB_HOST", value = var.db_host },
        { name = "DB_MASTER_SECRET_ARN", value = var.db_master_secret_arn },
        { name = "DB_NAME", value = var.db_name },
        { name = "DB_PORT", value = tostring(var.db_port) },
        { name = "DB_RUNTIME_SECRET_ARN", value = var.db_runtime_secret_arn },
        { name = "DB_SSLROOTCERT", value = "/srv/app/certs/rds-us-east-1-bundle.pem" },
        { name = "EMBEDDING_DIMENSIONS", value = tostring(var.embedding_dimensions) },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = local.region
          "awslogs-stream-prefix" = local.db_bootstrap_container
        }
      }
    }
  ])

  tags = {
    Name = local.db_bootstrap_name
  }
}
