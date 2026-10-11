output "cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.this.name
}

output "service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.app.name
}

output "task_definition_arn" {
  description = "ARN of the application task definition revision"
  value       = aws_ecs_task_definition.app.arn
}

output "log_group_name" {
  description = "Name of the application log group"
  value       = aws_cloudwatch_log_group.app.name
}
