variable "account_id" {
  description = "AWS account ID that owns the audit log bucket and trail."
  type        = string
}

variable "aws_region" {
  description = "AWS Region used in the globally unique S3 bucket name."
  type        = string
}

variable "cloudwatch_logs_group_arn" {
  description = "CloudWatch Logs group ARN, including the required trailing :*."
  type        = string
}

variable "cloudwatch_logs_role_arn" {
  description = "IAM role ARN that permits CloudTrail to write to CloudWatch Logs."
  type        = string
}

variable "project_name" {
  description = "Short name used to tag and name logging resources."
  type        = string
}

variable "tags" {
  description = "Tags applied to logging resources."
  type        = map(string)
  default     = {}
}
