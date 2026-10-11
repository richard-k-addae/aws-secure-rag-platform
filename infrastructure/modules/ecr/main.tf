data "aws_caller_identity" "current" {}

# Dedicated key for the application image repository. ECR works through
# grants it creates on this key when the repository is created, so the key
# policy only needs to delegate to IAM; no service or role is named here.
resource "aws_kms_key" "ecr" {
  description             = "Encrypts container images in the ${var.repository_name} ECR repository"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIamPolicies"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
    ]
  })

  tags = {
    Name = "rag-platform-${var.environment}-ecr-key"
  }
}

resource "aws_kms_alias" "ecr" {
  name          = "alias/rag-platform-${var.environment}-ecr"
  target_key_id = aws_kms_key.ecr.key_id
}

resource "aws_ecr_repository" "this" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }

  tags = {
    Name = var.repository_name
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name

  # AWS deletes the lifecycle policy with its repository, so recreate it
  # whenever the repository is replaced (the ARN only changes on replacement).
  lifecycle {
    replace_triggered_by = [
      aws_ecr_repository.this.arn
    ]
  }

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the most recent 20 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 20
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}