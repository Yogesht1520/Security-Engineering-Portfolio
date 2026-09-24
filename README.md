# Security-Engineering-Portfolio

<!--
  This file goes in a repo named EXACTLY the same as your GitHub username
  (e.g. if your username is "jsingh", create a repo called "jsingh/jsingh").
  GitHub automatically renders that repo's README.md on your profile page.
  Replace every [Yogesht1520] and [Your Name] placeholder below before publishing.
-->

<div align="center">

# Hi, I'm Yogesh Thakur 👋
### Security Engineer in progress — Cloud Security · Detection Engineering · DevSecOps

I build things to understand them, not just to pass exams. This portfolio is 8 hands-on
security engineering projects, each solving a real problem end-to-end — architecture,
implementation, and proof it actually works.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://www.linkedin.com/in/yogesht1520/)
[![Email](https://img.shields.io/badge/Email-Contact-red?logo=gmail)](mailto:yogesht1520@gmail.com)

</div>

---

## Why this portfolio exists

Certifications prove you know the theory. This portfolio proves I can build, break, and
defend the systems the theory describes. Each project below was built independently,
documented like a real engineering deliverable, and designed to connect to the others —
this isn't 8 disconnected tutorials, it's one security stack built in layers:

```
Detection Fundamentals  →  Automation & CI/CD  →  Cloud Infrastructure  →
Live Monitoring (SIEM)  →  Network Segmentation  →  Identity & Access  →
Incident Response
```

---

## 🗂️ The 8 Projects

### 1. [Secure Corporate Cloud Environment](./Secure%20Corporate%20Cloud%20Environment)
**The Problem:** Manually configured cloud environments drift, get misconfigured, and leave no audit trail.
**Architecture / Tools:** Terraform · AWS VPC/CloudTrail/CloudWatch · GitHub Actions · Checkov/tfsec
**Implementation:** A fully IaC-defined VPC with least-privilege security groups, CloudTrail + VPC Flow Logs for dual-layer visibility, and a CI/CD pipeline that lints, security-scans, and gates every infrastructure change before it merges.
**Proof:** `terraform plan` shows zero drift · CI blocks a deliberately-introduced `0.0.0.0/0` rule · root-login triggers an email alert within minutes
**Connects to:** Feeds network telemetry into →  [Enterprise SIEM & Live Threat Detection Lab](./siem-detection-lab)

---

### 2. [Automated Log Parser & Threat Report Generator](https://github.com/Yogesht1520/sec-portfolio-02-log-analyzer)
**The Problem:** Raw server logs contain evidence of attacks, but nobody reads thousands of lines by hand.
**Architecture / Tools:** Python (streaming parsers) · Jinja2 · Plotly · MaxMind GeoLite2
**Implementation:** A pluggable detection engine (SQLi, brute-force, path traversal, scanner fingerprints) that processes multi-GB logs without loading them into memory, and outputs a dark-themed, SOC-style HTML report.
**Proof:** Correctly flags 100% of injected attacks in a synthetic demo log · benchmarked throughput of 9,526 lines/sec
**Connects to:** Same detection philosophy as → [Enterprise SIEM & Live Threat Detection Lab](./siem-detection-lab), applied to static logs instead of live streams

---

### 3. [Hybrid Enterprise Identity & Conditional Access Lab](https://github.com/Yogesht1520/sec-portfolio-03-identity-lab)
**The Problem:** Identity, not the network, is the perimeter that actually gets attacked first.
**Architecture / Tools:** Microsoft Entra ID · Conditional Access · Microsoft Graph PowerShell
**Implementation:** A modeled enterprise identity tenant enforcing MFA for admin roles, geo-based access blocking, legacy-auth blocking, and risk-based sign-in policies — configured as code via Graph PowerShell, not clicked manually.
**Proof:** Screenshots of denied sign-in from a blocked region · MFA challenge triggered for an admin-role test account
**Connects to:** Identity-layer counterpart to → [Project 6 (Zero-Trust Network)](https://github.com/Yogesht1520/sec-portfolio-06-zero-trust-vpn)'s network-layer trust boundaries

---

### 4. [Enterprise SIEM & Live Threat Detection Lab](./siem-detection-lab)
**The Problem:** Logs without correlation and alerting are just noise nobody looks at until it's too late.
**Architecture / Tools:** Wazuh (OpenSearch-based SIEM) · a real internet-facing honeypot · custom MITRE-mapped detection rules
**Implementation:** A live SIEM ingesting real attack traffic from a deliberately exposed honeypot VM, with custom rules for brute-force and privilege escalation, visualized on a world-attack-map dashboard.
**Proof:** Dashboard showing real (not synthetic) internet attack traffic · a custom rule firing, mapped to a MITRE ATT&CK technique ID
**Connects to:** Natural home for telemetry from → [Secure Corporate Cloud Environment](./Secure%20Corporate%20Cloud%20Environment)'s VPC Flow Logs and → [Project 7](https://github.com/Yogesht1520/sec-portfolio-07-threat-intel-blacklister)'s IOC feed

---

### 5. 🌟 **FEATURED:** [Automated DevSecOps CI-CD Security Pipeline](./Automated%20DevSecOps%20CI-CD%20Security%20Pipeline)
**The Problem:** Security scanning that happens after deployment is security scanning that happens too late.
**Architecture / Tools:** GitHub Actions · TruffleHog · Trivy · Semgrep · SARIF/GitHub Code Scanning
**Implementation:** A shift-left pipeline that scans every push for leaked secrets, vulnerable dependencies, and insecure code patterns — and blocks the merge if anything HIGH/CRITICAL is found.
**Proof:** A PR carrying a fake secret and a known-vulnerable dependency is automatically blocked, then goes green after remediation. *(Check out the Open PR on this repo!)*
**Connects to:** The same CI/CD discipline is applied to infrastructure code in → [Secure Corporate Cloud Environment](./Secure%20Corporate%20Cloud%20Environment)

---

### 6. [Zero-Trust Network & VPN Topology Architecture](https://github.com/Yogesht1520/sec-portfolio-06-zero-trust-vpn)
**The Problem:** "Connected to the VPN" is too often treated as equivalent to "trusted" — that's the opposite of zero trust.
**Architecture / Tools:** WireGuard · nftables · per-peer network segmentation
**Implementation:** A real WireGuard gateway enforcing per-user access to isolated Dev/Prod/Corp-HR network segments, with defense-in-depth enforced at both the tunnel-routing layer and the firewall layer independently.
**Proof:** A contractor peer can reach Dev but is explicitly denied (and logged) trying to reach Prod or HR, even after deliberately weakening one enforcement layer
**Connects to:** Network-layer counterpart to → [Project 3 (Identity Lab)](https://github.com/Yogesht1520/sec-portfolio-03-identity-lab)'s identity-layer trust boundaries

---

### 7. [Automated Threat Intelligence & IP Blacklisting Engine](https://github.com/Yogesht1520/sec-portfolio-07-threat-intel-blacklister)
**The Problem:** Reacting to attacks after they happen is slower than defending against IPs already known to be malicious.
**Architecture / Tools:** Python · AbuseIPDB/AlienVault OTX APIs · SQLite · ipset/nftables
**Implementation:** A scheduled pipeline that collects, deduplicates, and confidence-scores malicious IPs from multiple free threat-intel feeds, then automatically enforces a TTL-based firewall blocklist — avoiding the common mistake of blocklists that only ever grow.
**Proof:** `ipset list` showing real, automatically-enforced entries · audit log showing add/expire decisions with source attribution
**Connects to:** Could enrich alerts in → [Enterprise SIEM & Live Threat Detection Lab](./siem-detection-lab) with known-bad-IP context

---

### 8. [Controlled Ransomware Simulation & Digital Forensics](https://github.com/Yogesht1520/sec-portfolio-08-dfir-ransomware-sim)
**The Problem:** Understanding an attack after it's already happened — using only forensic evidence — is a fundamentally different skill from preventing one.
**Architecture / Tools:** Air-gapped VirtualBox VM · Atomic Red Team · Volatility 3 · Autopsy
**Implementation:** A safe, non-destructive, MITRE-mapped attack simulation run inside a fully isolated VM, investigated blind using memory and disk forensics, and written up as a consulting-grade Incident Response report.
**Proof:** A full attack timeline reconstructed purely from Volatility/Autopsy output, delivered as a professional PDF report
**Note:** Built with an explicit safety-first methodology — network isolation verified before every run, no live malware samples used. See `SAFETY.md` in the repo.

---

## 🧠 How to read this portfolio

If you only have 5 minutes, look at **Project 4** (SIEM) and **Project 1** (Cloud IaC) —
together they show the full loop of *build secure infrastructure → generate telemetry →
detect threats in it live*.

If you want to see software engineering discipline specifically, look at **Project 5**
(CI/CD pipeline) and **Project 7** (threat-intel automation) — both are Python/pipeline-heavy
and show testing, adapter patterns, and idempotency.

If you want to see judgment and communication under pressure, read **Project 8**'s
Incident Response report — that's the artifact closest to what a real DFIR consultant delivers.

---

## 🛠️ Tech stack across the portfolio

![Terraform](https://img.shields.io/badge/-Terraform-844FBA?logo=terraform&logoColor=white)
![AWS](https://img.shields.io/badge/-AWS-232F3E?logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/-GitHub_Actions-2088FF?logo=githubactions&logoColor=white)
![Wazuh](https://img.shields.io/badge/-Wazuh-005571?logo=wazuh&logoColor=white)
![WireGuard](https://img.shields.io/badge/-WireGuard-88171A?logo=wireguard&logoColor=white)
![Microsoft Entra ID](https://img.shields.io/badge/-Entra_ID-0078D4?logo=microsoftazure&logoColor=white)
![Linux](https://img.shields.io/badge/-Linux-FCC624?logo=linux&logoColor=black)

Every tool used across all 8 projects is open source or free-tier — no paid licenses required to reproduce any of this work.

---

<div align="center">
<sub>Built and documented independently as a self-directed security engineering portfolio.</sub>
</div>
