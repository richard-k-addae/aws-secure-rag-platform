variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC the database runs in"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for the DB subnet group"
  type        = list(string)
}

variable "ecs_security_group_id" {
  description = "ID of the ECS task security group, the only permitted database client"
  type        = string
}

variable "engine_version" {
  description = "PostgreSQL major version. A major-only value lets RDS apply minor upgrades without Terraform drift"
  type        = string
  default     = "16"
}

variable "instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.micro"
}

variable "allocated_storage" {
  description = "Initial storage in GiB"
  type        = number
  default     = 20
}

variable "max_allocated_storage" {
  description = "Upper limit for storage autoscaling in GiB"
  type        = number
  default     = 50
}

variable "multi_az" {
  description = "Run a synchronous standby in a second Availability Zone"
  type        = bool
  default     = true
}

variable "db_name" {
  description = "Name of the application database"
  type        = string
  default     = "rag"
}

variable "db_port" {
  description = "PostgreSQL port"
  type        = number
  default     = 5432
}

variable "master_username" {
  description = "Master (bootstrap and migration) user name. Never used by the application at runtime"
  type        = string
  default     = "rag_admin"
}

variable "backup_retention_days" {
  description = "Days of automated backups to keep"
  type        = number
  default     = 7
}

variable "log_retention_days" {
  description = "Retention of the exported database log groups in days"
  type        = number
  default     = 365
}
