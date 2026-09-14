output "alb_security_group_id" {
  description = "ID of the security group for the future public ALB."
  value       = aws_security_group.alb.id
}

output "app_security_group_id" {
  description = "ID of the application-tier security group."
  value       = aws_security_group.app.id
}
