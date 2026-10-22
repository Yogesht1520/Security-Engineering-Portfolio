# 🔬 Controlled Ransomware Simulation & Digital Forensics Investigation

> **CONFIDENTIAL — Simulated Incident for Educational Purposes Only**
> Lead Investigator: Yogesh T | Role: DFIR Analyst | Classification: Portfolio / Educational

---

## Executive Overview

This project demonstrates a **complete, end-to-end Digital Forensics & Incident Response (DFIR) workflow**
using only open-source tools, executed entirely inside an air-gapped virtual machine. The goal is to
simulate realistic ransomware-adjacent behavior, acquire forensic evidence, and produce a professional-grade
Incident Response report — identical in structure to a real consulting deliverable.

> **Why behavioral simulation instead of live malware?**
> Using real ransomware samples introduces unacceptable risk (accidental detonation, legal exposure,
> AV evasion uncertainty) with zero additional learning benefit. Atomic Red Team tests and a
> purpose-written simulation script produce *identical* forensic artifacts — process trees, file-system
> mutations, registry changes, shadow-copy deletion attempts — while keeping the environment fully
> controlled and every action fully understood. This is the approach used by professional red teams
> and DFIR training programs. Choosing simulation over live malware is a judgment signal, not a limitation.

---

## High-Level Architecture

```
+-----------------------------------------------------+
|          Your Physical Host (read-only observer)     |
|                                                      |
|  +----------------------------------------------+   |
|  |  Isolated VM -- NO NETWORK ADAPTER ATTACHED  |   |
|  |                                              |   |
|  |  [Clean Snapshot] -> [Simulation] -> [Artifacts] |
|  +----------------------------------------------+   |
|                        |                             |
|           +------------+------------+                |
|           v                         v                |
|     [Memory Dump .raw]      [Disk Image .E01]        |
|           |                         |                |
|     [Volatility 3]            [Autopsy]              |
|           +------------+-----------+                 |
|                        v                             |
|            [Incident Response Report PDF]            |
+-----------------------------------------------------+
```

---

## Repository Structure

```text
ransomware-dfir-lab/
├── README.md                            <- Project overview and methodology
├── SAFETY.md                            <- Air-gap protocols & non-negotiable safety rules
├── .gitignore                           <- Excludes multi-GB raw evidence & internal prompts
├── docs/
│   └── INCIDENT_RESPONSE_REPORT.md      <- Primary deliverable (Executive consulting IR report)
├── simulation/
│   ├── custom_behavior_sim.py           <- Controlled ransomware simulation tool (v1.2.12)
│   ├── test_crash_recovery.py           <- 15-scenario automated unit & crash recovery suite
│   └── atomic_red_team_tests.md         <- MITRE ATT&CK test procedure plan
├── forensics/
│   ├── acquisition/
│   │   ├── memory_dump_steps.md         <- Memory capture SOP & procedure
│   │   ├── disk_image_steps.md          <- Disk imaging SOP & procedure
│   │   ├── DFIR-SimVM-memory.raw.sha256 <- SHA-256 verification hash for RAM dump
│   │   └── disk_image.vdi.sha256        <- SHA-256 verification hash for disk clone
│   ├── volatility_analysis/
│   │   ├── ANALYSIS_NOTES.md            <- Memory forensics investigation notes
│   │   ├── windows_info_output.txt      <- OS profile & kernel base
│   │   ├── pslist_output.txt            <- Active process enumeration
│   │   ├── psscan_output.txt            <- Unlinked / pool-tagged process scan
│   │   ├── pstree_output.txt            <- Process execution hierarchy
│   │   ├── cmdline_output.txt           <- Reconstructed process arguments & Notepad session
│   │   ├── netscan_output.txt           <- Network socket audit (air-gap verification)
│   │   └── malfind_output.txt           <- Code injection & memory protection scan
│   └── autopsy_analysis/
│       ├── ANALYSIS_NOTES.md            <- Disk forensics & MFT investigation notes
│       ├── deleted_files_report.md      <- Analysis of unallocated clusters & atomic swaps
│       ├── directory_mft_listing.csv    <- Cryptographic MFT record export (SHA-256)
│       └── timeline_export.csv          <- File modification timeline burst data
└── screenshots/
    ├── vm-network-adapter-disabled.png  <- Verification of hypervisor network isolation
    ├── network-connectivity-test.png    <- Guest ping failure verification (air-gap proof)
    ├── simulation-terminal-complete.png <- Simulation execution terminal output
    ├── encrypted-files-directory.png    <- Target directory showing .locked extensions
    ├── ransom-note-artifact.png         <- README_YOUR_FILES.txt extortion notice
    ├── autopsy-encrypted-directory.png  <- Autopsy MFT record explorer view
    ├── autopsy-timeline-counts.png      <- Autopsy macro activity spike graph
    └── autopsy-timeline.png             <- Autopsy micro-timeline showing 4s encryption burst
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Forensic Observable |
|---|---|---|
| Data Encrypted for Impact | T1486 | File rename artifacts, entropy change |
| Inhibit System Recovery | T1490 | `vssadmin delete shadows` in process history |
| Process Injection | T1055 | `malfind` output in Volatility |
| OS Credential Dumping | T1003 | LSASS access artifacts in memory |

---

## Tech Stack

| Layer | Tool | License | Cost |
|---|---|---|---|
| Virtualization | VirtualBox | GPLv2 | $0 |
| Simulation | Atomic Red Team | MIT | $0 |
| Memory Forensics | Volatility 3 | Volatility Software License | $0 |
| Disk Forensics | Autopsy + The Sleuth Kit | Apache-2.0 | $0 |
| Imaging | FTK Imager / dc3dd | Free / BSD | $0 |
| Reporting | Markdown -> Pandoc -> PDF | GPL/MPL | $0 |

---

## Phases

| Phase | Description | Status |
|---|---|---|
| **Phase 0** | Safe environment setup (VM, network isolation, baseline snapshot) | ✅ COMPLETE — Air-gap & baseline verified |
| **Phase 1** | Simulation execution (controlled ransomware simulation v1.2.12) | ✅ COMPLETE — 8 canary files encrypted, run ID `B67F15E3` |
| **Phase 2** | Evidence acquisition (8.13 GB RAM + 35.74 GB VMDK + SHA-256) | ✅ COMPLETE — Cryptographically signed & verified |
| **Phase 3** | Memory forensics — Volatility 3 blind analysis | ✅ COMPLETE — Process tree, cmdline, 0 sockets, clean memory |
| **Phase 4** | Disk forensics — Autopsy blind analysis | ✅ COMPLETE — MFT export, 4s encryption storm, timeline |
| **Phase 5** | Incident Response Report (primary deliverable) | ✅ COMPLETE — `docs/INCIDENT_RESPONSE_REPORT.md` finalized |
| **Phase 6** | Teardown and host cleanup | ✅ COMPLETE — Reverted to clean baseline snapshot |

> **GATE: Phase 1 is locked until `screenshots/vm-network-adapter-disabled.png` exists and is verified.**

---

## Primary Deliverable

`docs/INCIDENT_RESPONSE_REPORT.pdf` — A professional, 3-4 page consulting-grade IR report covering:
Executive Summary, Timeline of Events, IOCs, Technical Findings, Impact Assessment, Root Cause Analysis,
and Remediation Recommendations.

---

## Safety

All safety rules are documented in **[SAFETY.md](./SAFETY.md)**.
Network isolation is the single most important control in this project.

---

*This project was built as part of a Security Engineering Portfolio demonstrating practical DFIR competency.*
