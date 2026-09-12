variable "account_id" {
  description = "AWS account ID that owns the audit log bucket and trail."
  type        = string
}

variable "aws_region" {
  description = "AWS Region used in the globally unique S3 bucket name."
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
