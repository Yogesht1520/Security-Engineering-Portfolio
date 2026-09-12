# Secure Corporate Cloud Environment

Terraform infrastructure-security portfolio project.

## Phase 0 status

Bootstrap complete once `terraform init` succeeds from this directory. No AWS resources are defined or created in this phase.

## Prerequisites

- Terraform 1.6 or later
- AWS CLI authenticated through the default credential chain
- Git

## Initialize

```powershell
terraform init
```

Do not commit Terraform state files or AWS credentials.

## Phase 1 cost warning

Phase 1 creates one managed NAT Gateway and an Elastic IP address. A NAT Gateway is a billable AWS resource while it exists, with hourly and data-processing charges. Apply the stack only for testing, capture your verification screenshots, then run `terraform destroy` immediately. Do not continue to later phases until the destroy completes successfully.
