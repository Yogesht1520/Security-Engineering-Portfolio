# Automated DevSecOps CI/CD Security Pipeline

[![Security Pipeline](https://github.com/Yogesht1520/Security-Engineering-Portfolio/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/Yogesht1520/Security-Engineering-Portfolio/actions/workflows/security-pipeline.yml)

A production-grade, DevSecOps CI/CD pipeline built entirely with GitHub Actions and industry-standard open-source security tools. This project demonstrates advanced "shift-left" security, supply-chain integrity, and risk-based gate enforcement.

## 🏗️ Architecture

The pipeline implements a comprehensive Defense-in-Depth strategy across 5 distinct scanning layers, converging at a unified Security Gate that prevents vulnerable code from ever reaching the deployment phase.

```text
Code Push → [ Secrets | SAST | SCA | IaC | Container ] → Security Gate → SBOM Generation → GHCR Deploy
```

## 🛠️ Tech Stack & Tool Selection

| Layer | Tool | Justification |
|-------|------|---------------|
| **Secret Scanning** | TruffleHog | Scans full git history (not just working tree) to catch deleted secrets. |
| **SAST** (Code) | Semgrep | Uses the community `p/security-audit` ruleset. Exceptionally fast. |
| **SCA** (Dependencies) | Trivy | *Replaces Snyk.* Chosen to achieve best-in-class dependency scanning using a 100% open-source tool. |
| **IaC Security** | Checkov | Industry standard for Terraform misconfiguration detection. |
| **Container Security** | Trivy | Scans the built Docker layers for OS-level vulnerabilities before push. |
| **Supply Chain** | Trivy + GHCR | Generates CycloneDX SBOMs; uses SHA-pinned immutable GitHub Actions. |
| **Reporting UI** | GH Code Scanning | All tools normalize to SARIF for native inline PR annotations. |

## 📁 Repository Structure

```
Automated DevSecOps CI-CD Security Pipeline/
├── README.md
├── Dockerfile                  # Multi-stage build (intentionally vulnerable base)
├── .semgrep.yml                # SAST configuration
├── .trivyignore                # Documented risk exception management
├── app/
│   ├── requirements.txt        # Fully pinned transitive dependencies
│   ├── app.py                  # Vulnerable Flask app (SQLi vector)
│   └── config_example.py       # Synthetic credentials for TruffleHog detection
├── infra/
│   ├── main.tf                 # Vulnerable Terraform (Unrestricted SG ingress)
│   └── variables.tf
├── tests/
│   └── test_gate_logic.sh      # Unit tests for pipeline enforcement logic
├── .github/
│   └── workflows/
│       ├── security-pipeline.yml    # Main DevSecOps pipeline
│       ├── nightly-full-scan.yml    # Scheduled advisory scanning
│       └── test-security-gate.yml   # Pipeline integrity tests
└── docs/
    ├── PIPELINE_DESIGN.md           # Architecture and Branch Protection manual
    └── SCAN_RESULTS_WALKTHROUGH.md  # End-to-end vulnerability lifecycle story
```

## 🔒 Key Features (Production-Grade Enhancements)

1. **Risk-Based Severity Tiers**: The pipeline doesn't just blindly fail. It categorizes findings: CRITICAL/HIGH instantly block the build, MEDIUM surfaces as a warning, and LOW is informational.
2. **Immutable Supply Chain**: Every third-party GitHub Action in this repository is pinned to an immutable commit SHA (e.g., `actions/checkout@b4ffde65...`) rather than a mutable tag (`@v4`), neutralizing tag-rewriting supply chain attacks.
3. **Automated SBOMs**: A CycloneDX Software Bill of Materials is generated for the final container artifact automatically before it is pushed to the registry.
4. **Tested Pipeline Logic**: Security infrastructure should be treated as code. The core logic that evaluates the scanners and triggers the blocking gate is unit-tested in `tests/test_gate_logic.sh`.
5. **Unified Dashboard**: Developers receive a consolidated security metrics dashboard via the GitHub Actions Job Summary, displaying exactly what passed, what failed, and why.

## 🚀 Running the Tests

To verify the pipeline's Security Gate logic behaves correctly under various simulated scanner failure scenarios:

```bash
chmod +x tests/test_gate_logic.sh
./tests/test_gate_logic.sh
```

## 📖 Documentation

- **[Pipeline Design & Architecture](docs/PIPELINE_DESIGN.md)**: Details on the shift-left rationale and instructions for configuring branch protection rules.
- **[Catching a Vulnerability Walkthrough](docs/SCAN_RESULTS_WALKTHROUGH.md)**: A narrative walkthrough of how a developer experiences this pipeline when they accidentally commit a vulnerability, and how the pipeline prevents it from shipping.
