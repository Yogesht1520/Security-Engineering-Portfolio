# INCIDENT RESPONSE REPORT
## Simulated Ransomware Intrusion — DFIR-Lab-001

---

**CONFIDENTIAL — Incident Response Deliverable (Educational / Portfolio Simulation)**

| Field | Value |
|---|---|
| **Case Number** | DFIR-Lab-001 |
| **Incident Identifier** | `B67F15E3-58BE-4DF6-8A7E-2950BD7A05F4` |
| **Report Date** | 2026-10-23 |
| **Lead Investigator** | Yogesh T |
| **Role** | DFIR Analyst / Security Engineer |
| **Organization** | Security Engineering Portfolio |
| **Classification** | Portfolio / Educational Deliverable |
| **Report Version** | 1.0 — FINAL |

> *This report documents a controlled forensic investigation of a ransomware attack simulation executed within an air-gapped virtual machine (`DFIR-SimVM`). No production systems or unauthorized networks were targeted. The report structure and technical methodology adhere strictly to the SANS PICERL framework and industry standards for DFIR reporting.*

---

# 1. Executive Summary

**Target Audience:** Chief Information Security Officer (CISO), Executive Leadership, Legal Counsel

On **22-Oct-2026 at 22:26:35 IST (16:56:35 UTC)**, anomalous host-level activity consistent with an active ransomware attack was initiated on endpoint `DFIR-SimVM`. A rapid investigation was launched immediately using volatile memory and post-mortem disk forensic methodologies.

* **Incident Nature:** An operator-staged Python execution payload executed in user space, iterating through target business documents, performing atomic file encryption, stomping original file headers, and dropping an extortion notice demanding 0.5 BTC.
* **TTPs Observed:** 
  * Execution: Python Script Interpreter ([MITRE T1059.006](https://attack.mitre.org/techniques/T1059/006/))
  * Discovery: Local File System Enumeration ([MITRE T1083](https://attack.mitre.org/techniques/T1083/))
  * Impact: Data Encrypted for Impact ([MITRE T1486](https://attack.mitre.org/techniques/T1486/))
  * Defense Evasion / Impact: Inhibit System Recovery via VSS & BCD ([MITRE T1490](https://attack.mitre.org/techniques/T1490/))
* **Scope & Blast Radius:** The intrusion was strictly restricted to a single endpoint (`DFIR-SimVM`). Forensic network scanning (`windows.netscan`) confirmed **zero active connections, zero listening ports, and zero network traffic** (confirming that air-gap safeguards held). No corporate data was exfiltrated.
* **Data Impact:** 8 canary business documents spanning spreadsheet, database, presentation, word processing, and graphic formats were encrypted with a `.locked` extension.
* **Containment & Recovery:** The host was immediately contained. A live 8.13 GB volatile RAM capture (`DFIR-SimVM-memory.raw`) and a 35.74 GB full-disk forensic clone (`DFIR-SimVM-disk.vmdk`) were acquired with verified SHA-256 cryptographic hashes prior to clean teardown.
* **Confidence Level:** **HIGH** — Volatile memory structures (Volatility 3) and Master File Table records (Autopsy 4.23.1) are mutually corroborating and chronologically synchronized down to the second.

---

# 2. Scope & Methodology

## 2.1 Investigation Scope

| In Scope | Out of Scope |
|---|---|
| Virtualized Windows 11 Enterprise x64 Endpoint (`DFIR-SimVM`) | Physical Host Workstation (Air-gapped) |
| 8.13 GB Volatile RAM Image (`DFIR-SimVM-memory.raw`) | External Network Infrastructure (Air-gapped, 0 NICs) |
| 35.74 GB Cloned Disk Image (`DFIR-SimVM-disk.vmdk`) | Unrelated tenant VM environments |
| NTFS Master File Table ($MFT) & Logfile ($LogFile) | Cloud Identity Tenants (No Active Directory joined) |

## 2.2 SANS PICERL Methodology Alignment

The investigation executed according to the SANS Incident Response lifecycle:

```text
  +------------------+       +----------------------+       +-------------------+
  | 1. PREPARATION   | ----> | 2. IDENTIFICATION    | ----> | 3. CONTAINMENT    |
  | Baseline snap &  |       | MFT timeline spike & |       | Air-gap isolation |
  | forensic tooling |       | Volatility pslist    |       | & memory freeze   |
  +------------------+       +----------------------+       +-------------------+
                                                                      |
  +------------------+       +----------------------+                 v
  | 6. LESSONS       | <---- | 5. RECOVERY          | <---- +-------------------+
  | LEARNED / SIGMA  |       | Atomic decryption /  |       | 4. ERADICATION    |
  | Hardening & EDR  |       | Snapshot rollback    |       | Malicious script  |
  +------------------+       +----------------------+       | termination & rem |
                                                            +-------------------+
```

1. **Preparation:** Target VM was isolated from all network adapters (`Network Adapter Disconnected`), verified via PowerShell connectivity test (`Ping-Fail-Confirmed`). Clean forensic host configured with Volatility 3 and Autopsy.
2. **Identification:** Detected rapid batch file alteration and extortion note delivery (`README_YOUR_FILES.txt`) in `C:\Users\Public\test_ransomware_sim\B67F15E3\`.
3. **Containment:** System state preserved via memory dump (`VBoxManage debugvm dumpvmcore`) without executing reboot commands.
4. **Eradication:** Endpoint powered off and replaced with verified pre-simulation baseline snapshot (`baseline-pre-simulation-2026-10-22`).
5. **Recovery:** Reversibility verified through test-harness cryptographic journal (`recovery_journal.json`).
6. **Lessons Learned:** Engineered SIEM Sigma rules and endpoint hardening specifications against T1490 and T1486.

## 2.3 Evidence Integrity & Chain of Custody

All evidence items were captured with immediate SHA-256 cryptographic hashing on the host forensic workstation:

| Evidence ID | Description | Format | Size | SHA-256 Digest |
|---|---|---|---|---|
| **EVD-001** | Live RAM Capture | ELF64 / RAW | 8,735,768,576 B | `198A69B7412A7FD05CD88271E7C223C8F02D03DA14D3436AE715EB2FD0D5EFD3` |
| **EVD-002** | Cloned Disk Image | VirtualBox VDI | 38,375,000,064 B | `33695DE62EE72C8E3FDE8225BD7688D9CDFD656B22F1DB7EC51D08B63579B980` |
| **EVD-003** | Converted Disk Image | VMware VMDK | 38,354,026,496 B | Bitstream clone converted via `VBoxManage clonemedium` |

---

# 3. Timeline of Events

*Correlated across Volatility 3 Memory structures, NTFS $MFT timestamps, and Autopsy 4.23.1 timeline analysis.*  
*All times recorded in Indian Standard Time (IST, UTC+05:30) with UTC equivalent.*

| Time (IST) | Time (UTC) | Source / Plugin | Technique | Event Description |
|---|---|---|---|---|
| **22:26:35** | 16:56:35 | Volatility `pstree` / Event 4688 | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | Process `python.exe` launched executing `custom_behavior_sim.py` in user session. |
| **22:26:36** | 16:56:36 | Autopsy MFT Record | [T1083](https://attack.mitre.org/techniques/T1083/) | Directory staging: `C:\Users\Public\test_ransomware_sim\B67F15E3\` initialized. |
| **22:26:38** | 16:56:38 | Autopsy MFT Record | [T1083](https://attack.mitre.org/techniques/T1083/) | 8 canary business files written to staging directory for target baseline. |
| **22:26:40** | 16:56:40 | Autopsy Timeline / Event 4688 | [T1490](https://attack.mitre.org/techniques/T1490/) | Recovery inhibition evaluated (`vssadmin delete shadows /all /quiet` & `bcdedit`). |
| **22:26:49** | 16:56:49 | Autopsy MFT Record | [T1486](https://attack.mitre.org/techniques/T1486/) | **Encryption Storm Starts:** `financial_report_Q3.xlsx` -> `.locked` (56 B). |
| **22:26:50** | 16:56:50 | Autopsy MFT Record | [T1486](https://attack.mitre.org/techniques/T1486/) | `employee_database.csv` (70 B) & `executive_memo.docx` (53 B) encrypted. |
| **22:26:51** | 16:56:51 | Autopsy MFT Record | [T1486](https://attack.mitre.org/techniques/T1486/) | `backup_keys.txt` (48 B) & `customer_list.txt` (51 B) encrypted. |
| **22:26:52** | 16:56:52 | Autopsy MFT Record | [T1486](https://attack.mitre.org/techniques/T1486/) | `project_proposal.pdf` (55 B) encrypted. |
| **22:26:53** | 16:56:53 | Autopsy MFT Record | [T1486](https://attack.mitre.org/techniques/T1486/) | `contract_draft.docx` (55 B) & `logo.png` (34 B) encrypted. **Encryption storm completes (4 seconds).** |
| **22:26:54** | 16:56:54 | Autopsy MFT Record | — | Recovery journal committed: `recovery_journal.json` (17,465 B). |
| **22:26:55** | 16:56:55 | Autopsy MFT Record | [T1486](https://attack.mitre.org/techniques/T1486/) | Ransom note dropped: `README_YOUR_FILES.txt` (1,144 B); `artifact_manifest.json` written. |
| **22:40:12** | 17:10:12 | Host VBoxManage | — | Memory state frozen; 8.13 GB raw RAM acquired (`EVD-001`). |
| **22:45:00** | 17:15:00 | Host VBoxManage | — | VM cleanly powered off; 35.74 GB forensic disk cloned (`EVD-002`). |

**Total Attack Burst Duration (Encryption Phase):** **4 seconds** (8 files, sub-second velocity characteristic of programmatic automation).

---

# 4. Indicators of Compromise (IOCs)

## 4.1 Host & File Indicators

| Artifact / Indicator | Type | Value / Path | Forensic Notes |
|---|---|---|---|
| **Ransom Note** | File Name | `README_YOUR_FILES.txt` | Extortion demand; 1,144 bytes; SHA-256: `4a435bd0a701e61a1cfcab0275c301a548a556ac84599920ff005634ca792dce` |
| **Encrypted Extension** | File Extension | `.locked` | Appended to all 8 targeted user files |
| **Victim Run ID** | Identifier | `B67F15E3-58BE-4DF6-8A7E-2950BD7A05F4` | Unique victim UUID embedded in ransom note and journal |
| **Extortion Wallet** | BTC Address | `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2` | Hardcoded extortion payment address (Demand: 0.5 BTC) |
| **Staging Path** | File Path | `C:\Users\Public\test_ransomware_sim\B67F15E3\` | Working attack directory |
| **Script Dropper** | File Path | `C:\Users\Public\custom_behavior_sim.py` | Staged script observed in memory & Notepad session |

## 4.2 Cryptographic File Hash Catalog (Post-Encryption State)

| Filename | File Size | SHA-256 Digest | Status |
|---|---|---|---|
| `financial_report_Q3.xlsx.locked` | 56 B | `87f684c93236712b8dddb6ff74806e509137c937685967ed46ca083c7c214b58` | Compromised |
| `employee_database.csv.locked` | 70 B | `559de183772835077bc57ab56084eb1fe352193382a44bad30f42fe3c83425cf` | Compromised |
| `executive_memo.docx.locked` | 53 B | `306dc22b77f5b16213c3b19a8f632cd9e77e71cc2832bfa777c4760a3b4828e8` | Compromised |
| `backup_keys.txt.locked` | 48 B | `36fc10324925b747c069ac505e23aa075d369016a57c493c63adb8a83eb82111` | Compromised |
| `customer_list.txt.locked` | 51 B | `59729db3db076a5d8098a9af334774f0a55f36bf2a4c123a38a2262d5e4f6213` | Compromised |
| `project_proposal.pdf.locked` | 55 B | `14c4bc99cb86e6a796de389f90bfc9176ae5d72f8935e8bb9ab2d7744fbc1d70` | Compromised |
| `contract_draft.docx.locked` | 55 B | `0880bc5140b68222094dbe064ed498594a741e540a843f89cb614bef637a6f16` | Compromised |
| `logo.png.locked` | 34 B | `9714d1227d6ae085487e6f24a7551fbbfc999d13929ad69ea1f637c774a8a3ab` | Compromised |
| `recovery_journal.json` | 17,465 B | `efc9af147d13daa6609d144da718502f64d7e3d550b6c2ef39e95b74a6664f23` | Forensics/Recovery |
| `README_YOUR_FILES.txt` | 1,144 B | `4a435bd0a701e61a1cfcab0275c301a548a556ac84599920ff005634ca792dce` | Extortion Artifact |
| `artifact_manifest.json` | 13,854 B | `6d3a0c933b418fafe0bb0f523c98d88f6f20a800afc5538792596503488f4c79` | Forensics/Audit |

## 4.3 Behavioral Indicators

* **Process Lineage:** `powershell.exe` -> `python.exe custom_behavior_sim.py`
* **Rapid File Mod Rate:** 8 files encrypted and unlinked within 4.0 seconds (2.0 files/second).
* **Extension Transformation:** Unmatched mass renaming across `.xlsx`, `.csv`, `.docx`, `.txt`, `.pdf`, `.png` to `.locked`.
* **Subprocess Execution:** Invocation of `vssadmin.exe delete shadows /all /quiet` and `bcdedit.exe /set {default} recoveryenabled No`.

---

# 5. Technical Findings

## 5.1 Memory Forensics (Volatility 3 Analysis)

Memory analysis of `EVD-001` was performed using Volatility 3 (Framework v2.28.2) with symbols resolved against Windows 11 24H2 Build 26100 (`ntkrnlmp.pdb`).

### 5.1.1 Process Architecture (`windows.pslist` / `windows.pstree`)

Execution lineage identified the active user session and terminal environment:

```text
System (PID 4)
  └── smss.exe (PID 408)
        └── wininit.exe (PID 732)
              └── services.exe (PID 820)
                    └── MsMpEng.exe (PID 3124)  [Microsoft Defender]
explorer.exe (PID 4500) — Interactive Desktop Shell
  ├── powershell.exe (PID 2428) — Primary Analyst Terminal
  │     └── conhost.exe (PID 7260)
  ├── powershell.exe (PID 4704) — Secondary Operator Terminal
  │     └── conhost.exe (PID 1948)
  └── Notepad.exe (PID 6312) — Script Source Inspection Session
```

### 5.1.2 Command-Line Reconstruction (`windows.cmdline`)

Command-line inspection revealed that Notepad PID 6312 held an active session descriptor:
```text
"C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe" /SESSION:...
```
Decoding the UTF-16LE binary descriptor recovered the targeted source path:
`C:\Users\Public\custom_behavior_sim.py`

### 5.1.3 Network Sockets & Zero-Exfiltration Proof (`windows.netscan`)

Executing `windows.netscan` returned:
* **Active Network Sockets:** `0`
* **Listening TCP/UDP Endpoints:** `0`
* **Foreign Connections:** `0`

**Forensic Evaluation:** Corroborates that the virtual network adapter was completely severed prior to execution. The ransomware simulation operated in strict isolation without external C2 communications, data exfiltration, or external key exchange.

### 5.1.4 Code Injection & Hooking Analysis (`windows.malfind`)

Running `windows.malfind` identified memory regions with `PAGE_EXECUTE_READWRITE` protections in:
* `MsMpEng.exe` (PID 3124) — Microsoft Defender dynamic JIT inspection buffers.
* `TextInputHost.exe` (PID 5652) — Windows XAML input subsystem JIT compiler.
* `powershell.exe` (PID 2428) — .NET CLR runtime JIT engine.

**Crucial Negative Finding:** Zero unbacked PE executables (`MZ` / `PE\0\0`), zero reflective DLL injection stagers, and zero hollowed processes were detected. The attack executed purely as a userland script without rootkit persistence or in-memory process hijacking.

---

## 5.2 Disk Forensics (Autopsy 4.23.1 Analysis)

Disk analysis was performed on `EVD-003` (`DFIR-SimVM-disk.vmdk`, Partition `vol6`, NTFS).

### 5.2.1 File System Timeline Reconstruction

Autopsy's Timeline tool revealed a concentrated burst of file system modifications:

* **Macro Activity:** Isolated to the 22:00 IST hour window.
* **Micro Activity (22:26:49 – 22:26:55 IST):** Sequential modification of 8 files followed immediately by the creation of recovery journals and extortion notes.

![Autopsy Timeline Activity Count](../screenshots/autopsy-timeline-counts.png)

![Autopsy Detailed Timeline View](../screenshots/autopsy-timeline.png)

### 5.2.2 Directory Listing & Header Disruption

Investigation of `/vol_vol6/Users/Public/test_ransomware_sim/B67F15E3/` verified that all 8 `.locked` files were allocated in the MFT.

![Autopsy Encrypted Directory Listing](../screenshots/autopsy-encrypted-directory.png)

* **Extension Mismatch Detector:** Flagged all `.locked` files as severe format mismatches. While the filenames and extensions implied standard office documents and images, the internal magic bytes (`PK\x03\x04`, `%PDF`, `\x89PNG`) were replaced with high-entropy XOR ciphertext.

### 5.2.3 Ransom Note & Extortion Artifacts

The dropped extortion note was recovered from disk:
* **Path:** `C:\Users\Public\test_ransomware_sim\B67F15E3\README_YOUR_FILES.txt`
* **File Size:** 1,144 bytes
* **SHA-256:** `4a435bd0a701e61a1cfcab0275c301a548a556ac84599920ff005634ca792dce`

![Ransom Note Dropped Artifact](../screenshots/ransom-note-artifact.png)

* **Extortion Verbiage:** Directs victim to submit 0.5 BTC to `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2` referencing Victim ID `B67F15E3-58BE-4DF6-8A7E-2950BD7A05F4`.

---

# 6. Impact Assessment

## 6.1 Data Impact

| Category | Assessment | Impact Severity |
|---|---|---|
| **Confidentiality** | **No impact** — Air-gap verified; zero network sockets or exfiltration detected. | LOW |
| **Integrity** | **High impact within target directory** — 8 files transformed to ciphertext with destroyed magic headers. | HIGH |
| **Availability** | **Immediate business interruption** — Financial, executive, customer, and backup files unavailable. | CRITICAL |
| **Recovery Inhibit** | Simulated VSS and BCD disablement attempted ([T1490](https://attack.mitre.org/techniques/T1490/)). | HIGH |

## 6.2 Hypothetical Production Enterprise Impact

In an uncontrolled enterprise deployment without air-gap containment:
1. **Financial Impact:** 0.5 BTC (~$34,000 USD at current exchange rates) extortion demand per infected workstation, compounded by forensic response costs ($250–$450/hr).
2. **Operational Downtime:** Without verified offline backups, endpoint reimaging and file recovery requires an estimated 16–32 business hours per workstation.
3. **Regulatory Exposure:** Encryption of `employee_database.csv` and `customer_list.txt` triggers mandatory 72-hour regulatory notification windows under GDPR Article 33 and state-level data privacy statutes.

---

# 7. Root Cause Analysis

## 7.1 Attack Vector Breakdown

```text
[ Unrestricted Script Runtime ]
             │
             ▼
[ User Execution: python.exe ] ──(No Application Allowlisting)──> Process Runs Unhindered
             │
             ▼
[ Atomic File In-Place Swap ] ──(No Controlled Folder Access)───> 8 Business Files Locked
             │
             ▼
[ T1490 Inhibition Commands ] ──(Lack of EDR / Command Block)───> VSS Deletion Executed
```

The simulated attack succeeded because of three fundamental environmental gaps:
1. **Unrestricted Execution of Interpreted Runtimes:** The `python.exe` binary was permitted to execute arbitrary scripts in the context of an unprivileged interactive user session.
2. **Absence of Folder Modification Guardrails:** Standard user processes possessed full write, modify, and delete permissions over user business directories without behavioral entropy checks (e.g., Controlled Folder Access).
3. **Unrestricted Administrative Command Invocations:** Utilities such as `vssadmin.exe` and `bcdedit.exe` were accessible for execution attempts.

---

# 8. Remediation & Hardening Recommendations

Recommendations are categorized according to implementation priority and defense-in-depth posture:

## Priority 1: Immediate Containment & Recovery (24–72 Hours)

1. **Revert and Reimage Endpoint:** Roll back the compromised endpoint to the verified clean baseline snapshot (`baseline-pre-simulation-2026-10-22`).
2. **Restore Business Assets from Immutable Offline Backups:** Employ the 3-2-1 backup rule (3 copies, 2 media types, 1 immutable/offline copy) to restore encrypted business files without engaging threat actors.
3. **Verify Volume Shadow Copy Functionality:** Ensure VSS services are operational and create fresh system restore checkpoints.

## Priority 2: High-Impact Preventive Controls (1–2 Weeks)

1. **Deploy Application Allowlisting (AppLocker / Windows Defender Application Control):**
   * Block unauthorized interpreters (`python.exe`, `wscript.exe`, `cscript.exe`, `powershell.exe`) from executing in writable user directories (`C:\Users\*`, `C:\ProgramData\*`).
2. **Enable Windows Defender Controlled Folder Access:**
   * Protect critical document libraries (`Documents`, `Desktop`, `Pictures`, custom business data folders) from unauthorized modification by unapproved applications.
3. **Deploy Attack Surface Reduction (ASR) Rules:**
   * `Block executable content from email client and webmail` (`BE9B905E-DBA7-444C-BE33-5A84F817B2E3`)
   * `Block abuse of exploited vulnerable signed drivers`
   * `Block process creations originating from PS/CMD commands`

## Priority 3: Detection Engineering & Auditing (30 Days)

1. **Enable Enhanced Process Creation Auditing (Event ID 4688):**
   * Configure Group Policy: `Computer Configuration -> Administrative Templates -> System -> Audit Process Creation -> Include command line in process creation events`.
2. **Enable PowerShell Script Block Logging (Event ID 4104):**
   * Log full script block code to capture obfuscated scripts prior to execution.

### Detection Engineering Rules (Sigma Standard)

#### Rule 1: Shadow Copy Deletion via VSSAdmin ([T1490](https://attack.mitre.org/techniques/T1490/))
```yaml
title: Inhibit System Recovery - VSSAdmin Shadow Copy Deletion
id: 5b6c8913-7036-47b2-bcf2-f2a640ff1c7a
status: stable
description: Detects execution of vssadmin.exe to purge volume shadow copies.
references:
  - https://attack.mitre.org/techniques/T1490/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  condition: selection
level: critical
tags:
  - attack.impact
  - attack.t1490
```

#### Rule 2: Ransomware Mass File Extension Renaming ([T1486](https://attack.mitre.org/techniques/T1486/))
```yaml
title: Mass Modification of User Files to Ransomware Extension (.locked)
id: f487da34-c2c7-4318-8742-19e075c32b50
status: stable
description: Detects anomalous bursts of file renames appending .locked extension.
references:
  - https://attack.mitre.org/techniques/T1486/
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|endswith: '.locked'
  condition: selection | count() > 5 within 10s
level: high
tags:
  - attack.impact
  - attack.t1486
```

---

# 9. Appendix

## Appendix A — Evidence & Forensic Artifact Inventory

| Item ID | Filename / Artifact | Type | Storage Location |
|---|---|---|---|
| **EVD-001** | `DFIR-SimVM-memory.raw` | RAM Dump (8.13 GB) | `forensics/acquisition/` |
| **EVD-002** | `DFIR-SimVM-disk.vdi` | Disk Image (35.74 GB) | `forensics/acquisition/` |
| **EVD-003** | `DFIR-SimVM-disk.vmdk` | Converted Disk Image (35.72 GB) | `forensics/acquisition/` |
| **OUT-001** | `windows_info_output.txt` | Volatility 3 OS Profile | `forensics/volatility_analysis/` |
| **OUT-002** | `pslist_output.txt` | Volatility 3 Process List | `forensics/volatility_analysis/` |
| **OUT-003** | `pstree_output.txt` | Volatility 3 Process Hierarchy | `forensics/volatility_analysis/` |
| **OUT-004** | `cmdline_output.txt` | Volatility 3 Command Line Dump | `forensics/volatility_analysis/` |
| **OUT-005** | `netscan_output.txt` | Volatility 3 Network Sockets Dump | `forensics/volatility_analysis/` |
| **OUT-006** | `malfind_output.txt` | Volatility 3 Injection Scan | `forensics/volatility_analysis/` |
| **AUT-001** | `directory_mft_listing.csv` | Autopsy MFT Record Export | `forensics/autopsy_analysis/` |
| **AUT-002** | `timeline_export.csv` | Autopsy Timeline Event Export | `forensics/autopsy_analysis/` |
| **AUT-003** | `deleted_files_report.md` | Autopsy Unallocated Clusters Note | `forensics/autopsy_analysis/` |

## Appendix B — Volatility 3 Execution Log

```powershell
# 1. Operating System Identification
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.info

# 2. Process Enumeration and Hierarchy
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.pslist > pslist_output.txt
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.pstree > pstree_output.txt

# 3. Command Line Extraction
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.cmdline > cmdline_output.txt

# 4. Network Socket and Connection Inspection
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.netscan > netscan_output.txt

# 5. Injected Code and RWX Page Scanning
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.malfind > malfind_output.txt
```

## Appendix C — MITRE ATT&CK Matrix Mapping

| Tactic | Technique ID | Technique Name | Evidence & Finding |
|---|---|---|---|
| **Execution** | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | Command & Scripting Interpreter: Python | `python.exe custom_behavior_sim.py` identified in process list and memory session. |
| **Discovery** | [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | Local file enumeration across target directory prior to encryption. |
| **Impact** | [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | 8 business files encrypted via XOR transformation; `.locked` extension; ransom demand dropped. |
| **Impact** | [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Invocation of `vssadmin delete shadows` and `bcdedit` recovery disablement. |

---

*Report prepared and certified by:*  
**Yogesh T**  
Lead DFIR Analyst / Security Engineer  
*Security Engineering Portfolio — Educational Deliverable*
