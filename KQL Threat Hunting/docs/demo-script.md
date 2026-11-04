# HuntBook: 3-Minute Technical Interview Presentation & Demo Script

**Project:** HuntBook — Enterprise Threat Hunting & Detection-as-Code Platform  
**Target Roles:** Detection Engineer, Lead Threat Hunter, Senior SOC Analyst, Security Architect  
**Author:** Yogesh Thakur

---

## 🎯 The Hook (0:00 - 0:45): The Problem with Fragmented Threat Hunting

> *"In most modern enterprise SOCs running Microsoft Defender XDR and Sentinel, threat hunting queries are scattered across personal OneNote tabs, private repos, or stale bookmarks. When a query breaks because a Microsoft schema evolves or a field is deprecated, nobody knows until an incident is missed. Furthermore, junior analysts run unindexed KQL queries that scan petabytes of data, causing query timeouts and skyrocketing compute costs.*
>
> *I designed and built **HuntBook**—a production Detection-as-Code framework with 30 enterprise hunts, AST-level syntax and semantic type checking against live Microsoft schema definitions, deterministic synthetic attack simulation datasets, and a full React SOC console web portal."*

---

## 🔬 The Architecture (0:45 - 1:30): Detection Engineering Rigor

> *"What sets HuntBook apart is the automated CI/CD validation pipeline:*
>
> 1. **Schema Validation:** Every hunt is defined in YAML backed by strict JSON Schema (specifying MITRE ATT&CK technique, severity, false positives, triage steps, and parameters).
> 2. **KQL Abstract Syntax Tree (AST) & Semantic Checking:** Using Microsoft's `@kusto/language-service-next`, every KQL query is parsed into an AST and checked against 12 Microsoft table schemas (like `DeviceProcessEvents`, `SigninLogs`, and `DeviceNetworkEvents`). If an analyst typos a column name or passes the wrong data type to a function, the CI build fails immediately before deployment.
> 3. **Synthetic Telemetry Harness:** We built deterministic datagen generators that produce realistic attack graphs (password spray, phish-to-powershell, ransomware precursors) alongside high-volume benign enterprise noise. Every query is tested for true-positive detection and zero-baseline false alarms."*

---

## ⚡ The Live Demo (1:30 - 2:30): Flagship Hunt & SOC Workflow

> *"Let me show you our flagship Command-and-Control hunt: **HB-C2-001 (T1071 Periodic Beaconing)**.*
>
> *Traditional SIEM alerts fail on C2 beaconing because counting connections fires on legitimate services like Spotify or Teams. Instead, our KQL query leverages Kusto's `serialize` and `prev()` window operators to compute the inter-arrival delta times between consecutive connections. We then calculate the **Coefficient of Variation (Jitter Ratio)**—the ratio of standard deviation to mean delta.*
>
> *Benign human traffic has high jitter ($> 0.8$), while automated C2 implants like Cobalt Strike or Sliver have tight jitter ($< 0.35$). In one single-pass KQL query without external Python dependencies, we identify hidden beacons with sub-second execution.*
>
> *From the HuntBook Web Console, analysts can view the hunt, copy the optimized query, export a production-ready ARM/Bicep Sentinel Scheduled Analytics Rule with 1 click, or load a scenario into our local Kusto emulator lab API to inspect live telemetry."*

---

## 🏆 The Close (2:30 - 3:00): Impact & Honesty Metric

> *"HuntBook strictly follows what I call the **Honesty Rule**: every single hunt displays its true verification level (`syntax`, `synthetic`, or `tenant`). There are no mock percentages or unverified claims.
>
> The result is a library of 30 enterprise hunts mapped across 11 MITRE ATT&CK tactics, 100% CI pass rate, MITRE ATT&CK Navigator v4.5 exportability, and an extensible architecture built in TypeScript and React. I’m happy to dive deeper into any query or our AST parser implementation."*

