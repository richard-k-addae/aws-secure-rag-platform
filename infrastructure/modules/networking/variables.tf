variable "environment" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

variable "availability_zone_ids" {
  type = list(string)

  validation {
    condition     = length(var.availability_zone_ids) == 2
    error_message = "Exactly two availability zone IDs must be provided."
  }
}

variable "flow_log_retention_days" {
  type    = number
  default = 365
}
