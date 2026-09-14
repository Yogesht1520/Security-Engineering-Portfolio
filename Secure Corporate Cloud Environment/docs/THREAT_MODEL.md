# Threat Model

## Assets

- AWS control plane and root account
- CloudTrail audit records
- Network boundaries and routing configuration
- Alert delivery path

## Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Direct root-account use | CloudWatch metric filter, alarm, and SNS email notification |
| Missing audit evidence | Multi-Region CloudTrail, log-file validation, versioned S3 storage |
| Public log exposure | Block Public Access, SSE-S3, CloudTrail-only bucket policy |
| Flat network access | Public/private tiers and security-group-to-security-group application access |
| Broad remote administration | No public SSH/RDP rules |

## Boundaries

This project detects root usage; it does not prevent root usage or provide multi-account isolation. SNS email delivery depends on a confirmed subscription.
