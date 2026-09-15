terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# DELIBERATE SECURITY FLAW 1: Unrestricted ingress (0.0.0.0/0)
# Checkov will flag this as CKV_AWS_260 / CKV_AWS_24
resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Allow inbound web traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Vulnerability
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# DELIBERATE SECURITY FLAW 2: S3 bucket without encryption enabled
# Checkov will flag this as CKV_AWS_19
resource "aws_s3_bucket" "app_data" {
  bucket = "devsecops-app-data-${var.environment}"
}

# DELIBERATE SECURITY FLAW 3: EC2 instance without IMDSv2
# Checkov will flag this as CKV_AWS_28
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0" # Amazon Linux 2 (dummy)
  instance_type = "t2.micro"
  
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  tags = {
    Name = "VulnerableWebServer"
  }
}
