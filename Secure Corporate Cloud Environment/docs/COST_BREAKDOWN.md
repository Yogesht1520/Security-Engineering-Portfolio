# Cost Breakdown

| Component | Cost posture | Control |
| --- | --- | --- |
| VPC, subnets, route tables, IGW, security groups | No hourly charge | Terraform destroy removes test resources |
| Managed NAT Gateway | Paid hourly plus data processing | Use only during short verification tests |
| CloudTrail management events to S3 | First copy free; S3 usage billed | No data/network events |
| CloudTrail to CloudWatch Logs | Delivery and ingestion billed | Seven-day log retention and short tests |
| Metric filter, standard alarm, SNS email | Low-volume / Free Tier eligible | One metric, alarm, and email subscription |

Confirm current regional pricing and credit balance before every apply.
