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

  # No Secrets Manager access: the task definition references no secrets yet.
  # No KMS access: log encryption is done by the CloudWatch Logs service
  # principal, which the app log key policy authorizes for this log group.
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
        Sid    = "PullApplicationImageOnly"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = var.ecr_repository_arn
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
