variable "environment" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "flow_log_retention_days" {
  type    = number
  default = 365
}
