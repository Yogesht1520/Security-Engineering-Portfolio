# Secure Corporate Cloud Environment (IaC + DevSecOps)

> A production-shaped AWS environment, defined entirely as code, that is secure by
> construction and continuously verified — not secure because someone remembered
> to configure it correctly once.

![Terraform](https://img.shields.io/badge/-Terraform-844FBA?logo=terraform&logoColor=white)
![AWS](https://img.shields.io/badge/-AWS-232F3E?logo=amazonaws&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)
![Checkov](https://img.shields.io/badge/-Checkov-1F8ACB)
![tfsec](https://img.shields.io/badge/-tfsec-663399)

---

## The Problem

Most cloud security incidents aren't caused by sophisticated attacks — they're caused
by ordinary misconfiguration: a security group left open to `0.0.0.0/0`, a public S3
bucket, an unmonitored root account, infrastructure changes nobody reviewed. Manually
configured environments drift over time and rely on someone remembering every rule,
every time.

This project builds an AWS environment where that class of mistake is either
**impossible by design** or **caught automatically before it ever reaches production.**

## The Goal

Prove three things at once:

1. **I can design a secure cloud network** — proper segmentation, least-privilege
   access, and layered visibility.
2. **I can operate infrastructure the way a real team does** — through version
   control, automated review, and enforced security gates, not manual console changes.
3. **I understand the difference between "secure once" and "secure continuously"** —
   every control here is either self-enforcing or automatically re-verified on every
   change.

---

## Architecture

```
                              INTERNET
                                 │
                                 ▼
                         ┌───────────────┐
                         │      ALB      │
                         │  (HTTPS only) │
                         └───────┬───────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │  PRIVATE APP SUBNETS   │
                     │  (2 AZs, no direct     │
                     │   internet route)      │
                     └───────────┬───────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │  PRIVATE DATA SUBNETS  │
                     └───────────────────────┘

  ───────────────────────── AWS VPC ─────────────────────────

     Network Security                      Identity
          │                                    │
          ▼                                    ▼
  • Security Groups (chained,           • Scoped deploy role
    ALB → App → Data only)              • No long-lived root use
  • No NACL/SG allows                   • Least-privilege IAM
    0.0.0.0/0 except ALB:443            • MFA expected on
  • VPC Flow Logs (network-level          privileged roles
    visibility)


                    ┌────────────────────┐
                    │     CloudTrail      │  ← API activity: "who did what"
                    │  (multi-region,     │
                    │  log validation ON) │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌────────────────────┐
                    │   S3 Log Bucket     │
                    │  • Versioned        │
                    │  • Encrypted        │
                    │  • Public access    │
                    │    blocked          │
                    │  • Object Lock      │
                    │    (retention)      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌────────────────────┐
                    │  CloudWatch Metric  │
                    │       Filter        │
                    └──────────┬──────────┘
                               │
                               ▼
                             SNS
                               │
                               ▼
                    🚨 ROOT LOGIN ALERT
                    (break-glass only —
                     never routine)


          ── Delivery Pipeline (how changes reach AWS) ──

  Developer → GitHub → Pull Request → GitHub Actions:
                                       ├─ terraform fmt
                                       ├─ terraform validate
                                       ├─ tflint
                                       ├─ Checkov
                                       ├─ tfsec
                                       ├─ automated security tests
                                       └─ terraform plan
                                              │
                                              ▼
                                        Security Gate
                                              │
                                              ▼
                                       Merge → Apply → AWS
```

**Two independent visibility layers, on purpose:** CloudTrail answers "who called
which AWS API." VPC Flow Logs answer "what actually talked to what over the network."
Neither alone is enough — an attacker could act entirely inside the network without
touching the AWS API, or vice versa. Both feeds are also designed to plug directly
into a SIEM (see the companion [SIEM & Detection Lab](../sec-portfolio-04-siem-lab)
project in this portfolio).

---

## How It Works

1. **Network isolation by construction.** Only the ALB sits in public subnets. The
   application and data tiers live in private subnets with no direct internet route.
   Security Groups are chained (`ALB SG → App SG → Data SG`), so even a compromised
   app server can't be reached from the open internet, and can't reach the data tier
   except on the specific ports it needs.

2. **Every change is reviewed by machines before it's reviewed by anyone else.**
   Infrastructure changes are proposed as a pull request. GitHub Actions runs
   formatting checks, `terraform validate`, `tflint`, and two dedicated security
   scanners — Checkov and tfsec — against the plan. A set of automated security
   tests also assert specific invariants (SSH never open to `0.0.0.0/0`, S3 never
   public, CloudTrail log validation enabled, etc.). If anything fails, the PR is
   blocked from merging — a regression can't quietly slip back in.

3. **State is treated as sensitive, shared infrastructure — because it is.**
   Terraform state (which contains a full map of what exists, including some
   sensitive values) lives in an encrypted, versioned S3 backend with state locking,
   not on a laptop. This is what allows more than one person — or an automated
   pipeline — to safely operate this environment.

4. **Two independent logs, for two independent questions.** CloudTrail captures
   account-level API activity into an encrypted, versioned, publicly-blocked S3
   bucket with Object Lock retention enabled — versioning alone doesn't prevent
   deletion, so retention is what actually gives this tamper-resistance. VPC Flow
   Logs separately capture raw network traffic metadata.

5. **Root login is instrumented as an emergency signal, not a login method.**
   A CloudWatch metric filter watches CloudTrail specifically for root-account
   activity. If it ever fires, SNS emails an admin within minutes. The design
   assumption is explicit: **root is break-glass only, protected by MFA, and its use
   should be rare enough that an alert firing is itself meaningful** — this system is
   not built around administrators routinely logging in as root.

6. **The deploy identity is scoped, not privileged.** Whatever runs `terraform apply`
   — a person or the CI pipeline — uses a role scoped to exactly what deploying this
   stack requires. It is deliberately separate from any identity the application
   itself would run as.

---

## Tech Stack

| Layer | Tool | Cost |
|---|---|---|
| Infrastructure as Code | Terraform | Free |
| Cloud provider | AWS (Free Tier where possible) | ~$0–32/mo (NAT Gateway is the one paid line item — documented below) |
| CI/CD | GitHub Actions | Free |
| IaC linting | `tflint` | Free |
| IaC security scanning | Checkov, tfsec | Free |
| State backend | AWS S3 + native Terraform locking | Free tier |
| Diagramming | Mermaid / Draw.io | Free |

**Cost transparency:** the only component in this project that isn't strictly $0 is
the NAT Gateway (~$32/mo). This is documented explicitly rather than hidden — see
`docs/COST_BREAKDOWN.md` for a $0 alternative (a NAT instance) if you want to run this
completely free.

---

## Repository Structure

```
sec-portfolio-01-cloud-iac/
├── README.md
├── .github/workflows/
│   ├── terraform-ci.yml          # fmt, validate, tflint, checkov, tfsec, plan
│   └── security-tests.yml        # automated PASS/FAIL security assertions
├── main.tf
├── backend.tf                    # S3 remote state + locking config
├── variables.tf / outputs.tf
├── modules/
│   ├── network/                  # VPC, subnets, IGW, NAT, VPC Flow Logs
│   ├── security_groups/
│   ├── iam/                      # scoped deploy role, no long-lived keys
│   ├── logging/                  # CloudTrail + S3 (versioned, encrypted, locked)
│   └── alerting/                 # CloudWatch filter, SNS, root-login alert
├── tests/
│   └── security_assertions/      # automated PASS/FAIL checks (see below)
├── diagrams/
│   └── architecture.png
└── docs/
    ├── THREAT_MODEL.md
    ├── COST_BREAKDOWN.md
    └── IAM_BASELINE.md
```

---

## Security Gate in Action

This repo's CI pipeline enforces real security invariants automatically, for example:

```
✓ DB subnet has no public route
✓ App SG accepts traffic only from ALB SG
✓ SSH is not open to the internet
✓ S3 public access blocked
✓ S3 encryption enabled
✓ CloudTrail enabled with log file validation
✓ VPC Flow Logs enabled
```

To demonstrate this isn't just theoretical, a commit in this repo's history
deliberately introduces `cidr_blocks = ["0.0.0.0/0"]` on an ingress rule — the
pipeline fails and blocks the merge — followed by a remediation commit that fixes it
and passes. See `docs/CI_DEMO_WALKTHROUGH.md` for the annotated before/after.

---

## What I'd Do Differently at Scale

- Move from a single AWS account to AWS Organizations with Service Control Policies
- Federated/role-based deploy access (SSO) instead of a long-lived IAM deploy role
- GuardDuty + Security Hub for managed threat detection on top of this baseline
- Multi-account separation of dev/prod state and credentials

---

## Related Projects in This Portfolio

- **[SIEM & Detection Lab](../sec-portfolio-04-siem-lab)** — consumes this project's
  CloudTrail and VPC Flow Log output as live telemetry
- **[DevSecOps CI/CD Pipeline](../sec-portfolio-05-devsecops-pipeline)** — the same
  shift-left scanning philosophy applied to application code instead of infrastructure
