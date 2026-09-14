terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(var.tags, {
      Project     = var.project_name
      ManagedBy   = "Terraform"
      Environment = "portfolio"
    })
  }
}

data "aws_caller_identity" "current" {}

module "network" {
  source = "./modules/network"

  project_name         = var.project_name
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  tags                 = var.tags
}

module "security_groups" {
  source = "./modules/security_groups"

  project_name = var.project_name
  vpc_id       = module.network.vpc_id
  tags         = var.tags
}

module "alerting" {
  source = "./modules/alerting"

  admin_email  = var.admin_email
  project_name = var.project_name
  tags         = var.tags
}

module "logging" {
  source = "./modules/logging"

  account_id                = data.aws_caller_identity.current.account_id
  aws_region                = var.aws_region
  cloudwatch_logs_group_arn = module.alerting.cloudwatch_log_group_arn
  cloudwatch_logs_role_arn  = module.alerting.cloudwatch_logs_role_arn
  project_name              = var.project_name
  tags                      = var.tags
}
