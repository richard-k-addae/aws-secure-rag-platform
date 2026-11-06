variable "aws_region" {
  description = "Region for the evaluation user pool."
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
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "expected_account_id must be a 12-digit AWS account ID."
  }
}

variable "expires_on" {
  description = "Tag value (YYYY-MM-DD) after which the stack must not exist."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.expires_on))
    error_message = "expires_on must be YYYY-MM-DD."
  }
}
