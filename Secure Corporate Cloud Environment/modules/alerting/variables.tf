variable "admin_email" {
  description = "Email address that receives root-account activity alerts."
  type        = string
  sensitive   = true
}

variable "project_name" {
  description = "Short name used to tag and name alerting resources."
  type        = string
}

variable "tags" {
  description = "Tags applied to alerting resources."
  type        = map(string)
  default     = {}
}
