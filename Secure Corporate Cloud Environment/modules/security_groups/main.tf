#checkov:skip=CKV2_AWS_5: The ALB is intentionally out of scope; this group is attached when the future ALB is introduced.
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Public ALB: accepts HTTPS only and can reach the application tier over HTTPS."
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.project_name}-alb-sg"
    Tier = "edge"
  })
}

# The only internet-facing ingress in the project: HTTPS to the future public ALB.
resource "aws_vpc_security_group_ingress_rule" "alb_https_from_internet" {
  security_group_id = aws_security_group.alb.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Allow HTTPS from the internet to the public ALB."
}

# The ALB can send HTTPS only to application instances associated with the app SG.
resource "aws_vpc_security_group_egress_rule" "alb_https_to_app" {
  security_group_id            = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.app.id
  description                  = "Allow HTTPS from the ALB to the application tier."
}

#checkov:skip=CKV2_AWS_5: No application workload is deployed in this project; the group is created as a least-privilege boundary.
resource "aws_security_group" "app" {
  name        = "${var.project_name}-app-sg"
  description = "Application tier: accepts HTTPS only from the ALB security group."
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.project_name}-app-sg"
    Tier = "application"
  })
}

# No public CIDR can reach the application tier; only the ALB security group is trusted.
resource "aws_vpc_security_group_ingress_rule" "app_https_from_alb" {
  security_group_id            = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.alb.id
  description                  = "Allow HTTPS only from the public ALB security group."
}
