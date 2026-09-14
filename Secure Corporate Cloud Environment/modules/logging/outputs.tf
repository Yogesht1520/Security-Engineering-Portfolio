output "log_bucket_name" {
  description = "Name of the CloudTrail log bucket."
  value       = aws_s3_bucket.cloudtrail_logs.bucket
}

output "cloudtrail_arn" {
  description = "ARN of the multi-Region CloudTrail trail."
  value       = aws_cloudtrail.this.arn
}
