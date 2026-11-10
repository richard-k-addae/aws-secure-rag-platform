locals {
  # The M8.5 evaluation pool carries all three tags (set at creation by the
  # identity-eval root's default_tags and required by the harness pool guard).
  # Neither role can untag. rag-eval-terraform does hold cognito-idp:TagResource
  # (see CreateEvaluationUserPoolOnly), so while it existed it could in theory
  # have added this tag set to another existing pool in the same account and
  # region, bringing that pool into scope of these tag-scoped statements.
  evaluation_pool_tags = {
    "aws:ResourceTag/Environment" = "identity-eval"
    "aws:ResourceTag/Milestone"   = "M8.5"
    "aws:ResourceTag/Ephemeral"   = "true"
  }

  # The pool ID does not exist before creation, so the ARN is account- and
  # region-bound and the tags select the evaluation pool.
  user_pool_arns = ["arn:aws:cognito-idp:${var.aws_region}:${var.expected_account_id}:userpool/*"]
}

# --- Trust: one explicit operator principal, MFA required -------------------------

data "aws_iam_policy_document" "operator_trust" {
  statement {
    sid     = "OperatorWithMfaOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.operator_principal_arn]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

# --- rag-eval-terraform: create/read/delete the evaluation Cognito stack ----------
# Derived from the AWS provider (5.100.0) create, read and delete paths for
# aws_cognito_user_pool, aws_cognito_user_group and aws_cognito_user_pool_client.
# No Update* or UntagResource: the wrapper (evaluations/live/terraform_runner.py)
# accepts only all-create or all-delete plans. No ListUserPools: Terraform does not
# call it; the operator lists pools separately.
#
# This role was temporary, assumable only with MFA, and was destroyed after the
# M8.5 live validation passed.

data "aws_iam_policy_document" "terraform_permissions" {
  # CreateUserPool has no resource type (the pool does not exist yet), so AWS
  # requires Resource "*". TagResource is included because Cognito required
  # separate tagging authorization when Terraform created the pool with the
  # required M8.5 tags (observed during M8.5). Both actions are bounded by the
  # region, the exact aws:RequestTag/* values and the aws:TagKeys allowlist below;
  # the account is the one the credentials belong to (allowed_account_ids). The
  # conditions constrain the tags in the request, not which pool is tagged, so
  # TagResource could also have applied this tag set to an existing pool.
  statement {
    sid    = "CreateEvaluationUserPoolOnly"
    effect = "Allow"
    actions = [
      "cognito-idp:CreateUserPool",
      "cognito-idp:TagResource",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = ["aws-secure-rag-platform"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Environment"
      values   = ["identity-eval"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Milestone"
      values   = ["M8.5"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Ephemeral"
      values   = ["true"]
    }

    condition {
      test     = "ForAllValues:StringEquals"
      variable = "aws:TagKeys"
      values   = ["Project", "Environment", "Milestone", "ManagedBy", "Ephemeral", "ExpiresOn"]
    }
  }

  statement {
    sid    = "ManageEvaluationUserPoolOnly"
    effect = "Allow"
    actions = [
      "cognito-idp:DescribeUserPool",
      "cognito-idp:GetUserPoolMfaConfig",
      "cognito-idp:ListTagsForResource",
      "cognito-idp:DeleteUserPool",
      "cognito-idp:CreateGroup",
      "cognito-idp:GetGroup",
      "cognito-idp:DeleteGroup",
      "cognito-idp:CreateUserPoolClient",
      "cognito-idp:DescribeUserPoolClient",
      "cognito-idp:DeleteUserPoolClient",
    ]
    resources = local.user_pool_arns

    dynamic "condition" {
      for_each = local.evaluation_pool_tags
      content {
        test     = "StringEquals"
        variable = condition.key
        values   = [condition.value]
      }
    }
  }
}

# --- rag-eval-harness: synthetic users and admin auth in the evaluation pool ------
# Exactly the calls made by CognitoAdmin in evaluations/live/m8_5_cognito.py.

data "aws_iam_policy_document" "harness_permissions" {
  statement {
    sid    = "EvaluationUserPoolUsersOnly"
    effect = "Allow"
    actions = [
      "cognito-idp:DescribeUserPool",
      "cognito-idp:DescribeUserPoolClient",
      "cognito-idp:AdminCreateUser",
      "cognito-idp:AdminSetUserPassword",
      "cognito-idp:AdminAddUserToGroup",
      "cognito-idp:AdminRemoveUserFromGroup",
      "cognito-idp:AdminInitiateAuth",
      "cognito-idp:AdminUserGlobalSignOut",
      "cognito-idp:AdminDeleteUser",
      "cognito-idp:AdminGetUser",
      "cognito-idp:ListUsers",
    ]
    resources = local.user_pool_arns

    dynamic "condition" {
      for_each = local.evaluation_pool_tags
      content {
        test     = "StringEquals"
        variable = condition.key
        values   = [condition.value]
      }
    }
  }
}

# --- Roles (names are matched exactly by evaluations/live/aws_identity.py) --------

resource "aws_iam_role" "terraform" {
  name                 = "rag-eval-terraform"
  description          = "M8.5 temporary: Terraform for the identity-eval Cognito stack only. Destroy after M8.5."
  assume_role_policy   = data.aws_iam_policy_document.operator_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "terraform" {
  name   = "m85-identity-eval-cognito-lifecycle"
  role   = aws_iam_role.terraform.id
  policy = data.aws_iam_policy_document.terraform_permissions.json
}

resource "aws_iam_role" "harness" {
  name                 = "rag-eval-harness"
  description          = "M8.5 temporary: live Cognito harness for the identity-eval pool only. Destroy after M8.5."
  assume_role_policy   = data.aws_iam_policy_document.operator_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "harness" {
  name   = "m85-identity-eval-cognito-harness"
  role   = aws_iam_role.harness.id
  policy = data.aws_iam_policy_document.harness_permissions.json
}
