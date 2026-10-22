# 🔬 Controlled Ransomware Simulation & Digital Forensics Investigation

> **CONFIDENTIAL — Simulated Incident for Educational Purposes Only**  
> Lead Investigator: Yogesh T | Role: DFIR Analyst | Classification: Portfolio / Educational

---

## Executive Overview

This project demonstrates a **complete, end-to-end Digital Forensics & Incident Response (DFIR) workflow** using open-source tools, executed inside an air-gapped virtual machine. The goal is to simulate realistic ransomware-adjacent behavior, acquire forensic evidence, perform memory and disk analysis, and produce an executive-grade Incident Response report mirroring real-world consulting deliverables.

> **Why behavioral simulation instead of live malware?**  
> Using real ransomware samples introduces unacceptable risk (accidental detonation, legal exposure, AV evasion uncertainty) with zero additional learning benefit. Atomic Red Team tests and a purpose-written simulation script produce *relevant, controlled forensic observables* — process trees, file-system mutations, registry changes, shadow-copy deletion attempts — while keeping the environment fully controlled and every action fully understood. This is the approach used by professional red teams and DFIR training programs. Choosing simulation over live malware is a deliberate judgment signal, not a limitation.

---

## High-Level Architecture

```text
+--------------------------------------------------------------------------+
|                 Physical Forensic Workstation (Observer)                 |
|                                                                          |
|  +--------------------------------------------------------------------+  |
|  |           Isolated Guest VM (DFIR-SimVM, Windows 11 Enterprise)     |  |
|  |           Network Adapter: NOT ATTACHED (Strict Air-Gap)           |  |
|  |                                                                    |  |
|  |  [Staged Code & Baseline Snapshot] -> [Simulation Execution]       |  |
|  +--------------------------------------------------------------------+  |
|                           |                             |                |
|           +---------------+---------------+             |                |
|           v                               v             v                |
|  [Live RAM Acquisition]          [Power-off Clone]  [Teardown Revert]    |
|  DFIR-SimVM-memory.raw           DFIR-SimVM-disk.vdi   100% Snapshot     |
|  (8.13 GB ELF64 Core Dump)       (35.74 GB VDI Clone)   Restoration      |
|           |                               |                              |
|           v                               v                              |
|   [Volatility 3 Framework 2.28.2] [Autopsy 4.23.1 via VMDK]              |
|   - Process Tree & Cmdline        - NTFS $MFT Cryptographic Listing      |
|   - 0 Active Sockets (netscan)    - 4-Second File Transformation Burst   |
|   - Clean Memory Protections      - Extension Mismatch Detection         |
|           +-------------------------------+                              |
|                           v                                              |
|      [Incident Response Report: docs/INCIDENT_RESPONSE_REPORT.md]        |
+--------------------------------------------------------------------------+
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
│   ├── TEST_RESULTS.md                  <- 15/15 passed unit test execution record & environment
│   └── atomic_red_team_tests.md         <- MITRE ATT&CK test procedure plan (Reference-only)
├── forensics/
│   ├── acquisition/
│   │   ├── EVIDENCE_MANIFEST.md         <- Master evidence inventory & chain-of-custody ledger
│   │   ├── memory_dump_steps.md         <- Memory capture SOP & procedure
│   │   ├── disk_image_steps.md          <- Disk imaging SOP & procedure
│   │   ├── DFIR-SimVM-memory.raw.sha256 <- SHA-256 verification hash for RAM dump
│   │   ├── DFIR-SimVM-disk.vdi.sha256   <- SHA-256 verification hash for VDI disk clone
│   │   └── DFIR-SimVM-disk.vmdk.sha256  <- SHA-256 verification hash for derived VMDK
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
│       └── timeline_export.csv          <- Correlated forensic timeline export
└── screenshots/
    ├── vm-network-adapter-disabled.png  <- Verification of hypervisor network isolation
    ├── network-connectivity-test.png    <- Guest ping failure verification (guest network isolation test)
    ├── simulation-terminal-complete.png <- Simulation execution terminal output
    ├── encrypted-files-directory.png    <- Target directory showing .locked extensions
    ├── ransom-note-artifact.png         <- README_YOUR_FILES.txt extortion notice
    ├── autopsy-encrypted-directory.png  <- Autopsy MFT record explorer view
    ├── autopsy-timeline-counts.png      <- Autopsy macro activity spike graph
    └── autopsy-timeline.png             <- Autopsy micro-timeline showing 4s encryption burst
```

---

## Tool Version & Executable Provenance

To ensure forensic reproducibility, exact tool versions and verified binary digests are documented below:

| Tool | Exact Release Version | Binary Executable SHA-256 Digest | Role | Execution Host | Invocation Method |
|---|---|---|---|---|---|
| **Volatility 3** | Framework 2.28.2 | `664102407BC13906AC0A401A737028334907C0E235AB9DFAAF94A301A50687B3` | Volatile Memory Forensics | Windows 11 Physical Host | `vol.exe -f <raw> <plugin>` |
| **Autopsy** | 4.23.1 (TSK 4.12.1) | `EE790ADFCF8436D7B128DDB43D6F6DF1A8404DF7612972B2BEF7022B4F27BF69` | Post-Mortem Disk & MFT Analysis | Windows 11 Physical Host | GUI / SQLite Timeline Engine |
| **VirtualBox** | 7.1.6 r167084 | `178E016ED38CB6E369A5C17C6C960C176674B9C864030D8CE0AD2867613BECFF` | Hypervisor & Acquisition | Windows 11 Physical Host | `VBoxManage.exe` CLI |
| **Python (Host)** | 3.13.1 | Built-in CPython Host Distribution | Volatility & Hash Runtime | Windows 11 Physical Host | Host Python Runtime |
| **Python (Guest)**| 3.13.1 | Built-in CPython Guest Distribution | Simulator Execution Engine | `DFIR-SimVM` (Windows 11) | Guest Python Runtime |

---

## Offline Evidence Retention Policy

In adherence to DFIR best practices and repository constraints:
* **Large Evidence Images Retained Offline:** The primary 8.13 GB volatile RAM capture (`DFIR-SimVM-memory.raw`), the 35.74 GB disk clone (`DFIR-SimVM-disk.vdi`), and the 35.72 GB derived container (`DFIR-SimVM-disk.vmdk`) are retained offline on encrypted analyst storage (`E:\ForensicEvidence\DFIR-Lab-001\`) and excluded from Git via `.gitignore`.
* **Cryptographic Verification Ledger:** Full SHA-256 verification hashes for each image are tracked in **[`forensics/acquisition/EVIDENCE_MANIFEST.md`](./forensics/acquisition/EVIDENCE_MANIFEST.md)** and individual untruncated `.sha256` files.

---

## Air-Gap & Code Staging Protocol

To ensure strict network isolation without contaminating the environment:
1. **Script Staging:** For this investigation, the simulation code was staged in `C:\Users\Public\custom_behavior_sim.py` prior to final baseline snapshotting. An approved alternative workflow uses a read-only VirtualBox Virtual Optical Disc (ISO) to mount test scripts into the VM.
2. **Adapter Disablement:** The virtual network adapter was set to **"Not Attached"** in VirtualBox hypervisor settings.
3. **Dual Verification:** Guest network isolation was independently verified by:
   - Capturing hypervisor settings (`screenshots/vm-network-adapter-disabled.png`).
   - Running continuous ping sweeps inside the guest showing 100% packet loss (`screenshots/network-connectivity-test.png`).
4. **Baseline Snapshot:** The clean baseline snapshot (`baseline-pre-simulation-2026-10-22`) was taken *only after* network isolation was confirmed.

---

## MITRE ATT&CK Coverage

| Technique | ID | Forensic Observable | Evidence Source |
|---|---|---|---|
| Command and Scripting: Python | T1059.006 | Process tree, cmdline session descriptor | Volatility 3 (Memory) |
| File and Directory Discovery | T1083 | Local target directory file enumeration | Autopsy (MFT / Timeline) |
| Data Encrypted for Impact | T1486 | 4-second burst, .locked extensions, ransom note | Autopsy (MFT / Timeline) |
| Inhibit System Recovery | T1490 | Simulated evaluation logged in stdout & log (no live deletion executed) | `simulation_log.txt` (Contextual: Autopsy BCD query) |

---

## Investigation Phases & Status

| Phase | Description | Deliverable / Artifact | Status |
|---|---|---|---|
| **Phase 0** | Safe Environment Setup | Network isolation confirmed, baseline snapshot captured | ✅ **COMPLETE** |
| **Phase 1** | Controlled Simulation Execution | 8 canary files transformed, run ID `B67F15E3`, test harness passed ([TEST_RESULTS.md](./simulation/TEST_RESULTS.md)) | ✅ **COMPLETE** |
| **Phase 2** | Evidence Acquisition | 8.13 GB RAM (`.raw`) + 35.74 GB Disk (`.vmdk`), cryptographically hashed | ✅ **COMPLETE** |
| **Phase 3** | Memory Forensics (Volatility 3) | Process tree, Notepad session decode, no active socket structures in RAM, clean memory | ✅ **COMPLETE** |
| **Phase 4** | Disk Forensics (Autopsy 4.23.1) | MFT extraction, 4-second file transformation timeline, extension mismatch analysis | ✅ **COMPLETE** |
| **Phase 5** | Incident Response Report | Executive consulting deliverable: [docs/INCIDENT_RESPONSE_REPORT.md](./docs/INCIDENT_RESPONSE_REPORT.md) | ✅ **COMPLETE** |
| **Phase 6** | Teardown & Cleanup | `DFIR-SimVM` cleanly restored to baseline pre-simulation snapshot | ✅ **COMPLETE** |

---

## Primary Deliverable
 
The primary deliverable is **[`docs/INCIDENT_RESPONSE_REPORT.md`](./docs/INCIDENT_RESPONSE_REPORT.md)** — a formal, consulting-grade Incident Response Report structured around the SANS PICERL lifecycle. 

> **Deliverable Format Notice:**  
> The report is maintained directly in GitHub-flavored Markdown (`docs/INCIDENT_RESPONSE_REPORT.md`) for version control, interactive file/code linking, and GitHub web viewing. For client presentation or archival submission, it renders seamlessly to a formal corporate PDF (e.g., via Pandoc, VS Code Markdown PDF, or browser print-to-PDF).

It covers:
* **Executive Summary:** Incident scope, blast radius, and business impact for leadership and legal counsel.
* **Correlated Timeline:** Correlating Volatility memory structures and Autopsy NTFS MFT records down to the second.
* **Cryptographic Recovery Verification:** Complete before-and-after SHA-256 verification proving 100% data recovery without paying extortion.
* **Indicators of Compromise (IOCs):** Hashes, file paths, wallet addresses, and process commands.
* **Technical Deep-Dive:** Volatility 3 process trees, command lines, memory protections, and Autopsy timeline analysis.
* **Remediation & Sigma Rules:** Priority 1–3 security controls and vendor-agnostic Sigma rules for T1490 and T1486.

---

## Safety

All safety rules are documented in **[SAFETY.md](./SAFETY.md)**.  
Network isolation is the single most critical control in this project.

---

*This project was built as part of a Security Engineering Portfolio demonstrating practical DFIR competency.*
