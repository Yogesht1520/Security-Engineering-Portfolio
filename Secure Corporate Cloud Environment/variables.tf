variable "aws_region" {
  description = "AWS Region in which to create the stack."
  type        = string
  default     = "eu-north-1"
}

variable "project_name" {
  description = "Short name used to tag and name project resources."
  type        = string
  default     = "secure-corp-env"
}

variable "vpc_cidr" {
  description = "IPv4 CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "Two public subnet CIDR blocks, one for each Availability Zone."
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "Two private subnet CIDR blocks, one for each Availability Zone."
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "tags" {
  description = "Additional tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "admin_email" {
  description = "Email address that receives root-account activity alerts."
  type        = string
  sensitive   = true
}
