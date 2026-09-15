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

# FIXED SECURITY FLAW 1: Removed unrestricted ingress
resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Allow inbound web traffic"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FIXED SECURITY FLAW 2: Enabled S3 bucket encryption
resource "aws_s3_bucket" "app_data" {
  bucket = "devsecops-app-data-${var.environment}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_data_encryption" {
  bucket = aws_s3_bucket.app_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# FIXED SECURITY FLAW 3: Enforced IMDSv2 on EC2 instance
resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0" # Amazon Linux 2 (dummy)
  instance_type = "t2.micro"
  
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name = "SecureWebServer"
  }
}
