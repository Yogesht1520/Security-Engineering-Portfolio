output "vpc_id" {
  description = "ID of the secure corporate environment VPC."
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets."
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "IDs of the private subnets."
  value       = module.network.private_subnet_ids
}

output "nat_gateway_id" {
  description = "ID of the managed NAT Gateway. This is a billable resource while it exists."
  value       = module.network.nat_gateway_id
}

output "alb_security_group_id" {
  description = "ID of the public ALB security group."
  value       = module.security_groups.alb_security_group_id
}

output "app_security_group_id" {
  description = "ID of the private application-tier security group."
  value       = module.security_groups.app_security_group_id
}

output "cloudtrail_log_bucket_name" {
  description = "Name of the private S3 bucket that stores CloudTrail logs."
  value       = module.logging.log_bucket_name
}

output "cloudtrail_arn" {
  description = "ARN of the multi-Region CloudTrail trail."
  value       = module.logging.cloudtrail_arn
}

output "root_activity_alarm_arn" {
  description = "ARN of the CloudWatch alarm for direct root-account activity."
  value       = module.alerting.root_activity_alarm_arn
}
