variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC the security groups and endpoints belong to"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs that host the interface endpoints"
  type        = list(string)
}

variable "private_route_table_id" {
  description = "Private route table that receives the S3 gateway endpoint route"
  type        = string
}

variable "app_port" {
  description = "Port the application container listens on"
  type        = number
  default     = 8000
}
