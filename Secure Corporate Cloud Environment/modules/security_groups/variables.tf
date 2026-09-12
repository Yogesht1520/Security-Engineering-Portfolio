variable "project_name" {
  description = "Short name used to tag and name security resources."
  type        = string
}

variable "vpc_id" {
  description = "ID of the VPC in which to create the security groups."
  type        = string
}

variable "tags" {
  description = "Tags applied to security group resources."
  type        = map(string)
  default     = {}
}
