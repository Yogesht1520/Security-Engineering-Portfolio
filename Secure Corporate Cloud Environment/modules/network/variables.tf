variable "project_name" {
  description = "Short name used to tag and name network resources."
  type        = string
}

variable "vpc_cidr" {
  description = "IPv4 CIDR block for the VPC."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "Exactly two public subnet CIDR blocks."
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_cidrs) == 2 && alltrue([for cidr in var.public_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "public_subnet_cidrs must contain exactly two valid IPv4 CIDR blocks."
  }
}

variable "private_subnet_cidrs" {
  description = "Exactly two private subnet CIDR blocks."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_cidrs) == 2 && alltrue([for cidr in var.private_subnet_cidrs : can(cidrnetmask(cidr))])
    error_message = "private_subnet_cidrs must contain exactly two valid IPv4 CIDR blocks."
  }
}

variable "tags" {
  description = "Tags applied to network resources."
  type        = map(string)
  default     = {}
}
