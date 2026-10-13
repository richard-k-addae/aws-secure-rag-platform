variable "environment" {
  description = "Environment name (e.g. dev, prod)"
  type        = string
}

variable "retention_in_days" {
  description = "CloudWatch log retention in days for the metrics log group"
  type        = number
  default     = 365
}

variable "namespace" {
  description = "CloudWatch custom metrics namespace"
  type        = string
  default     = "SecureRAGPlatform"
}

variable "tags" {
  description = "Additional tags to apply to observability resources"
  type        = map(string)
  default     = {}
}
