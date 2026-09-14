output "cloudwatch_log_group_arn" {
  description = "CloudWatch Logs group ARN formatted for CloudTrail."
  value       = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
}

output "cloudwatch_logs_role_arn" {
  description = "IAM role CloudTrail assumes to write to CloudWatch Logs."
  value       = aws_iam_role.cloudtrail_logs.arn
}

output "root_activity_alarm_arn" {
  description = "ARN of the root-account activity alarm."
  value       = aws_cloudwatch_metric_alarm.root_activity.arn
}
