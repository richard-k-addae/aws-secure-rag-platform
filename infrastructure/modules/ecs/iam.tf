# Two separate roles. The execution role is used by Fargate itself to pull the
# image and deliver logs. The task role is what the application code runs as.

locals {
  bedrock_inference_profile_arn = "arn:aws:bedrock:${local.region}:${local.account_id}:inference-profile/${var.bedrock_inference_profile_id}"

  # Only ECS tasks in this account and region may assume either role.
  ecs_tasks_assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEcsTasksInThisAccount"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.account_id
          }
          ArnLike = {
            "aws:SourceArn" = "arn:aws:ecs:${local.region}:${local.account_id}:*"
          }
        }
      },
    ]
  })
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-ecs-execution-role"
  assume_role_policy = local.ecs_tasks_assume_role_policy

  tags = {
    Name = "${local.name}-ecs-execution-role"
  }
}

resource "aws_iam_role_policy" "execution" {
  name = "${local.name}-ecs-execution"
  role = aws_iam_role.execution.id

  # Secrets: only the rag_app runtime secret that the task definition injects
  # as DATABASE_URL, never the master secret. KMS: only to let Secrets Manager
  # decrypt that secret. Log encryption needs no KMS access here; it is done
  # by the CloudWatch Logs service principal under the app log key policy.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # GetAuthorizationToken does not support resource-level scoping.
        Sid      = "EcrAuth"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "PullApprovedEcrImagesOnly"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = compact([var.ecr_repository_arn, var.adot_ecr_repository_arn])
      },
      {
        # No logs:CreateLogGroup: the log group is created in logging.tf.
        Sid    = "WriteApplicationLogsOnly"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.app.arn}:*"
      },
      {
        Sid      = "ReadRuntimeDatabaseSecretOnly"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = var.db_runtime_secret_arn
      },
      {
        # Required because the secret uses a customer-managed key.
        Sid      = "DecryptRuntimeSecretViaSecretsManagerOnly"
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

resource "aws_iam_role" "task" {
  name               = "${local.name}-ecs-task-role"
  assume_role_policy = local.ecs_tasks_assume_role_policy

  tags = {
    Name = "${local.name}-ecs-task-role"
  }
}

resource "aws_iam_role_policy" "task" {
  name = "${local.name}-ecs-task-bedrock"
  role = aws_iam_role.task.id

  # InvokeModel only. Converse is authorized as bedrock:InvokeModel, and the
  # application does not stream, so InvokeModelWithResponseStream is omitted.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeApprovedInferenceProfile"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = local.bedrock_inference_profile_arn
      },
      {
        # The generation model is reachable only through the approved profile.
        Sid      = "InvokeGenerationModelViaProfileOnly"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = [for r in var.bedrock_inference_profile_regions : "arn:aws:bedrock:${r}::foundation-model/${var.bedrock_generation_model_id}"]
        Condition = {
          StringEquals = {
            "bedrock:InferenceProfileArn" = local.bedrock_inference_profile_arn
          }
        }
      },
      {
        Sid      = "InvokeEmbeddingModel"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = "arn:aws:bedrock:${local.region}::foundation-model/${var.bedrock_embedding_model_id}"
      },
    ]
  })
}

# The ADOT collector runs inside the task as a sidecar and needs IAM permissions
# to emit Embedded Metric Format (EMF) logs to the dedicated metrics log group.
# Scoped strictly to the metrics log group ARN.
resource "aws_iam_role_policy" "task_metrics" {
  count = var.enable_adot_sidecar ? 1 : 0

  name = "${local.name}-ecs-task-metrics"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PublishEmfMetricsToCloudWatchLogsOnly"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${var.metrics_log_group_arn}:*"
      },
    ]
  })
}
