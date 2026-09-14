output "vpc_id" {
  description = "ID of the VPC."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets by subnet name."
  value       = { for name, subnet in aws_subnet.public : name => subnet.id }
}

output "private_subnet_ids" {
  description = "IDs of the private subnets by subnet name."
  value       = { for name, subnet in aws_subnet.private : name => subnet.id }
}

output "nat_gateway_id" {
  description = "ID of the managed NAT Gateway."
  value       = aws_nat_gateway.this.id
}
