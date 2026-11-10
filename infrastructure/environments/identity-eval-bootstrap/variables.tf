variable "aws_region" {
  description = "Region of the M8.5 evaluation user pool; the role policies are scoped to it."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.aws_region == "us-east-1"
    error_message = "M8.5 is approved for us-east-1 only."
  }
}

variable "expected_account_id" {
  description = "The only AWS account this root may touch."
  type        = string

  validation {
    condition     = var.expected_account_id == "376129869231"
    error_message = "expected_account_id must be the project account 376129869231."
  }
}

variable "operator_principal_arn" {
  description = "The single IAM user in the project account allowed to assume both evaluation roles, with MFA. Supplied at plan time; never committed."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::376129869231:user/[A-Za-z0-9+=,.@_/-]{1,512}$", var.operator_principal_arn))
    error_message = "operator_principal_arn must be an IAM user ARN in account 376129869231 (arn:aws:iam::376129869231:user/<name>); roles, the root user, wildcards and other accounts are refused."
  }
}

variable "expires_on" {
  description = "Tag value (YYYY-MM-DD) after which the roles must not exist."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.expires_on))
    error_message = "expires_on must be YYYY-MM-DD."
  }
}
