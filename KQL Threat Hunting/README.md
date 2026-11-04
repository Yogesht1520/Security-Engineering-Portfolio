# HuntBook: KQL Threat Hunting Library & Lab

> **A locally runnable, synthetic-telemetry-validated KQL threat hunting and detection-as-code platform, designed around Microsoft Defender XDR and Sentinel schemas.**  
> Authored by **Yogesh Thakur** · Status: **v1.0.0 Complete**

[![CI Status](https://img.shields.io/badge/CI-passing-brightgreen)]()
[![Validation Level](https://img.shields.io/badge/Validation-synthetic%20(100%25)-blue)]()
[![Web Console](https://img.shields.io/badge/Web%20Console-React%2018%20%2B%20Tailwind-blue)]()
[![Lab Mode](https://img.shields.io/badge/Lab%20Runtime-Kusto%20Emulator%20%2B%20Fastify-purple)]()
[![Hunts Authored](https://img.shields.io/badge/Hunts-30%20%2F%2030-brightgreen)]()
[![Tests](https://img.shields.io/badge/Tests-60%20passed%20%7C%200%20failed-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v17-red)]()

---

## 🎯 What is HuntBook?

HuntBook is a **detection-as-code library of 30 original KQL threat hunting queries** mapped to the MITRE ATT&CK framework across Identity, Endpoint, Email, Cloud, Persistence, Lateral Movement, Ransomware, and Command & Control.

Every hunt in this repository is:
1. **Defined as Code:** Paired `.kql` query and `.hunt.yml` metadata (threat hypothesis, primary tables, false-positive sources, tuning guidance, SOC triage steps).
2. **Validated in CI:** Schema linting and KQL abstract syntax tree (AST) & semantic type-checking against 12 Microsoft table schemas via `@kusto/language-service-next`.
3. **Tested against Synthetic Attack Telemetry:** Deterministically seeded attack scenarios and benign noise evaluated in local CI and emulator test harnesses.
4. **Exportable & Publishable:** Generates a SOC-grade web catalog with an ATT&CK coverage matrix and 1-click Microsoft Sentinel analytics rule YAML exports.

---

## 🔬 Transparent Validation Levels

In security engineering, claiming a detection works without proof is a liability. Every hunt in HuntBook is strictly tagged with its verified validation level:

| Level | Badge | Meaning & Evidence |
|---|---|---|
| `static` | ![static](https://img.shields.io/badge/level-static-gray) | KQL query parsed and type-checked against supplied Microsoft table schemas in CI using `@kusto/language-service-next`. |
| `emulator` | ![emulator](https://img.shields.io/badge/level-emulator-purple) | Query executed directly against a local Kusto container (`kustainer-linux`). |
| `synthetic` | ![synthetic](https://img.shields.io/badge/level-synthetic-blue) | Tested against seeded attack and benign telemetry in a reproducible test harness. |
| `tenant` | ![tenant](https://img.shields.io/badge/level-tenant-green) | Verified in a live Microsoft Sentinel or Defender XDR tenant (documented with notes). |

---

## 📊 Complete Hunt Catalog (30 / 30)

| Area | ID | Hunt Title | MITRE ATT&CK | Platform | Primary Table | Level |
|---|---|---|---|---|---|---|
| **Identity** | `HB-ID-001` | Password spray against multiple accounts | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Sentinel | `SigninLogs` | `synthetic` |
| **Identity** | `HB-ID-002` | Targeted brute force followed by success | [T1110](https://attack.mitre.org/techniques/T1110/) | Sentinel | `SigninLogs` | `synthetic` |
| **Identity** | `HB-ID-003` | Impossible travel between distant regions | [T1078](https://attack.mitre.org/techniques/T1078/) | Sentinel | `SigninLogs` | `synthetic` |
| **Identity** | `HB-ID-004` | MFA fatigue attack followed by success | [T1621](https://attack.mitre.org/techniques/T1621/) | Sentinel | `SigninLogs` | `synthetic` |
| **Identity** | `HB-ID-005` | Legacy authentication protocol use | [T1078](https://attack.mitre.org/techniques/T1078/) | Sentinel | `SigninLogs` | `synthetic` |
| **Identity** | `HB-ID-006` | Highly privileged directory role assigned | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | Sentinel | `AuditLogs` | `synthetic` |
| **Endpoint** | `HB-EP-001` | Office app spawning script interpreter | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Defender XDR | `DeviceProcessEvents` | `synthetic` |
| **Endpoint** | `HB-EP-002` | Encoded PowerShell command execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Defender XDR | `DeviceProcessEvents` | `synthetic` |
| **Endpoint** | `HB-EP-003` | Ingress LOLBin download (certutil/bitsadmin) | [T1105](https://attack.mitre.org/techniques/T1105/) | Defender XDR | `DeviceProcessEvents` | `synthetic` |
| **Endpoint** | `HB-EP-004` | Suspicious LSASS memory access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Defender XDR | `DeviceEvents` | `synthetic` |
| **Endpoint** | `HB-EP-005` | Defender Antivirus exclusion added | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Defender XDR | `DeviceRegistryEvents` | `synthetic` |
| **Endpoint** | `HB-EP-006` | Windows event log cleared | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Defender XDR | `DeviceEvents` | `synthetic` |
| **Persistence** | `HB-PS-001` | Registry Run key persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Defender XDR | `DeviceRegistryEvents` | `synthetic` |
| **Persistence** | `HB-PS-002` | Scheduled task creation by uncommon parent | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Defender XDR | `DeviceProcessEvents` | `synthetic` |
| **Persistence** | `HB-PS-003` | New Windows service installed | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Defender XDR | `DeviceEvents` | `synthetic` |
| **Persistence** | `HB-PS-004` | WMI Event Subscription Persistence | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | Defender XDR | `DeviceEvents` | `synthetic` |
| **Lateral** | `HB-LM-001` | Rare RDP fan-out to multiple hosts | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Defender XDR | `DeviceLogonEvents` | `synthetic` |
| **Lateral** | `HB-LM-002` | Remote service or PsExec-like execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Defender XDR | `DeviceProcessEvents` | `synthetic` |
| **Lateral** | `HB-LM-003` | SMB admin share access fan-out | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Defender XDR | `DeviceNetworkEvents` | `synthetic` |
| **Email** | `HB-EM-001` | Inbound email with risky executable attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Defender XDR | `EmailAttachmentInfo` | `synthetic` |
| **Email** | `HB-EM-002` | Safe Links click on potential phishing URL | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Defender XDR | `UrlClickEvents` | `synthetic` |
| **Email** | `HB-EM-003` | Suspicious inbox rule (forward / delete) | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | Defender XDR | `CloudAppEvents` | `synthetic` |
| **Cloud** | `HB-CL-001` | Anomalous mass cloud file download | [T1530](https://attack.mitre.org/techniques/T1530/) | Defender XDR | `CloudAppEvents` | `synthetic` |
| **Cloud** | `HB-CL-002` | OAuth application consent with sensitive scopes | [T1528](https://attack.mitre.org/techniques/T1528/) | Sentinel | `AuditLogs` | `synthetic` |
| **Cloud** | `HB-CL-003` | Sign-in from Tor exit node or anonymizer | [T1090](https://attack.mitre.org/techniques/T1090/) | Sentinel | `SigninLogs` | `synthetic` |
| **Cloud** | `HB-CL-004` | Azure resource deletion burst | [T1485](https://attack.mitre.org/techniques/T1485/) | Sentinel | `AzureActivity` | `synthetic` |
| **Ransomware** | `HB-RW-001` | Shadow copy deletion & recovery inhibition | [T1490](https://attack.mitre.org/techniques/T1490/) | Defender XDR | `DeviceProcessEvents` | `synthetic` |
| **Ransomware** | `HB-RW-002` | Ransomware mass file rename with encrypted extension | [T1486](https://attack.mitre.org/techniques/T1486/) | Defender XDR | `DeviceFileEvents` | `synthetic` |
| **Ransomware** | `HB-RW-003` | Safe-Mode or boot recovery disabled via bcdedit | [T1490](https://attack.mitre.org/techniques/T1490/) | Defender XDR | `DeviceProcessEvents` | `synthetic` |
| **C2** | `HB-C2-001` | Command and Control periodic beaconing detection | [T1071](https://attack.mitre.org/techniques/T1071/) | Defender XDR | `DeviceNetworkEvents` | `synthetic` |

---

## ⚡ CLI & Tooling Reference

```bash
# Validate all 30 hunts against JSON Schemas & KQL AST semantics
node packages/cli/dist/cli.js validate

# Generate synthetic attack & baseline telemetry
node packages/cli/dist/cli.js generate

# Run synthetic test assertions (60 tests)
node packages/cli/dist/cli.js test

# Build catalog.json, coverage.json, and navigator-layer.json
node packages/cli/dist/cli.js build

# Launch the SOC Console Web Application locally
pnpm --filter @huntbook/web dev

# (Optional) Launch Local Lab Mode with Kusto Emulator
docker compose up -d kusto-emulator
pnpm --filter @huntbook/lab-api start

# Export any hunt to a Microsoft Sentinel Analytics Rule YAML
node packages/cli/dist/cli.js export sentinel HB-C2-001
```

---

## 📚 Interview Kit & Documentation

- [End-to-End Threat Investigation Case Study (Operation BlackShard)](docs/incident-investigation-case-study.md)
- [Detection Engineering Masterclass: Building HuntBook from First Principles](docs/detection-engineering-masterclass.md)
- [3-Minute Technical Interview Demo Script](docs/demo-script.md)
- [Top 10 Technical Interview Questions & Deep Answers](docs/interview-faq.md)
- [System Architecture & Detection Pipeline](docs/architecture.md)
- [Hunt Note 0001: Baseline Noise Tuning](docs/hunt-notes/0001-baseline-noise-tuning.md)
- [Hunt Note 0002: C2 Periodic Beaconing Detection](docs/hunt-notes/0002-c2-beaconing-detection.md)
- [Hunt Note 0003: Ransomware Inhibiting System Recovery](docs/hunt-notes/0003-ransomware-inhibiting-system-recovery.md)

---

## 🗺️ Project Roadmap & Phases

- [x] **Phase 0: Foundations and Spike** (Repository skeleton, ADRs, Kusto AST semantic analysis spike)
- [x] **Phase 1: Content MVP** (10 flagship hunts, `huntbook validate`, CI workflow, README)
- [x] **Phase 2: Test Harness & Synthetic Data** (Deterministic scenario engine, baseline noise, passing tests)
- [x] **Phase 3: Catalog, Coverage & Exporters** (Catalog builder, ATT&CK Navigator layer, Sentinel exporter, 20 hunts)
- [x] **Phase 4: Web UI** (SOC console static catalog, Monaco editor, coverage heatmap, hash routing, release workflow)
- [x] **Phase 5: Lab Mode & Scenario Replay** (Fastify Lab API, Docker Compose local execution, safety guards)
- [x] **Phase 6: Polish & Interview Kit** (30 hunts, flagship hunt write-ups, 3-minute demo script, interview FAQ)

---

## 🛠️ Tech Stack

- **Language & Runtime:** TypeScript 5.x, Node.js 22 LTS
- **Monorepo:** pnpm workspaces
- **KQL Analysis:** `@kusto/language-service-next`
- **Execution & Lab:** Microsoft Kusto Emulator (`kustainer-linux`)
- **Metadata Validation:** JSON Schema (`ajv`, `ajv-formats`)
- **Exporters:** Microsoft Sentinel Analytics Rule YAML, MITRE ATT&CK Navigator v4.5 JSON layer
- **Web Console:** React 18, Vite, Tailwind CSS, Monaco Editor, Apache ECharts

---

## 📄 License

MIT © [Yogesh Thakur](LICENSE)
