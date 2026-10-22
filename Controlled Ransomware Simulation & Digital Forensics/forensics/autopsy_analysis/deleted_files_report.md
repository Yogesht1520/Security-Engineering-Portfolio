# Deleted & Renamed Files Report — Autopsy Analysis
# Phase 4 — Disk Forensics

> **Investigator:** Yogesh T (Lead DFIR Analyst)  
> **Evidence Source:** `forensics/acquisition/DFIR-SimVM-disk.vmdk`  
> **Simulation Run ID:** `B67F15E3-58BE-4DF6-8A7E-2950BD7A05F4`  
> **Target Folder:** `C:\Users\Public\test_ransomware_sim\B67F15E3\`  
> **Tool:** Autopsy 4.23.1 > Data Sources > File Views / MFT Directory Listing  

---

## Overview

This report documents files that were created, encrypted, renamed, or unlinked during the ransomware attack simulation.
In this incident, the ransomware employed an atomic staging and replacement mechanism (`.stage.tmp` -> rename to `.locked` -> original file unlinked), creating distinct forensic artifacts across the NTFS Master File Table (MFT).

---

## Encrypted & Renamed Files Table

| # | Original Filename | Encrypted Artifact Name | Size | MFT Modification Time (IST) | Cryptographic SHA-256 Digest |
|---|---|---|---|---|---|
| 1 | `financial_report_Q3.xlsx` | `financial_report_Q3.xlsx.locked` | 56 B | 2026-10-22 22:26:49 | `87f684c93236712b8dddb6ff74806e509137c937685967ed46ca083c7c214b58` |
| 2 | `employee_database.csv` | `employee_database.csv.locked` | 70 B | 2026-10-22 22:26:50 | `559de183772835077bc57ab56084eb1fe352193382a44bad30f42fe3c83425cf` |
| 3 | `executive_memo.docx` | `executive_memo.docx.locked` | 53 B | 2026-10-22 22:26:50 | `306dc22b77f5b16213c3b19a8f632cd9e77e71cc2832bfa777c4760a3b4828e8` |
| 4 | `backup_keys.txt` | `backup_keys.txt.locked` | 48 B | 2026-10-22 22:26:51 | `36fc10324925b747c069ac505e23aa075d369016a57c493c63adb8a83eb82111` |
| 5 | `customer_list.txt` | `customer_list.txt.locked` | 51 B | 2026-10-22 22:26:51 | `59729db3db076a5d8098a9af334774f0a55f36bf2a4c123a38a2262d5e4f6213` |
| 6 | `project_proposal.pdf` | `project_proposal.pdf.locked` | 55 B | 2026-10-22 22:26:52 | `14c4bc99cb86e6a796de389f90bfc9176ae5d72f8935e8bb9ab2d7744fbc1d70` |
| 7 | `contract_draft.docx` | `contract_draft.docx.locked` | 55 B | 2026-10-22 22:26:53 | `0880bc5140b68222094dbe064ed498594a741e540a843f89cb614bef637a6f16` |
| 8 | `logo.png` | `logo.png.locked` | 34 B | 2026-10-22 22:26:53 | `9714d1227d6ae085487e6f24a7551fbbfc999d13929ad69ea1f637c774a8a3ab` |

---

## Dropped Extortion & Journal Artifacts

| Artifact | Purpose | Size | MFT Timestamp (IST) | Cryptographic SHA-256 Digest |
|---|---|---|---|---|
| `recovery_journal.json` | Atomic recovery journal (tracks pre/post hashes) | 17,465 B | 2026-10-22 22:26:54 | `efc9af147d13daa6609d144da718502f64d7e3d550b6c2ef39e95b74a6664f23` |
| `README_YOUR_FILES.txt` | Extortion demand ransom note | 1,144 B | 2026-10-22 22:26:55 | `4a435bd0a701e61a1cfcab0275c301a548a556ac84599920ff005634ca792dce` |
| `artifact_manifest.json` | High-fidelity execution manifest | 13,854 B | 2026-10-22 22:26:55 | `6d3a0c933b418fafe0bb0f523c98d88f6f20a800afc5538792596503488f4c79` |
| `simulation_log.txt` | Complete stdout / stderr runtime log | 8,462 B | 2026-10-22 22:26:55 | `e132277562d6420367d964891ccee11b36fbe50f85cb66c85b1c83a82f64603a` |

---

## Volume Shadow Copy (VSS) & Boot Configuration Assessment

| Mechanism | Technique ID | Forensic Observation on Disk |
|---|---|---|
| **VSS Catalog** | T1490 | Command simulated in log-only mode; actual live shadow copies were unmolested on system volume |
| **Boot Configuration Data** | T1490 | Autopsy Timeline recorded an active inspection of `/EFI/Microsoft/Boot/BCD` at hour 22:00 IST |

---

## Recovery Feasibility Assessment

| Recovery Vector | Feasibility | Method / Mechanism | Confidence |
|---|---|---|---|
| **Decryption via Known Key** | **100% Guaranteed** | Single-byte XOR key (`0xAB`) reversal | High |
| **Recovery via Recovery Journal** | **100% Guaranteed** | Reversal through `custom_behavior_sim.py --restore --manifest artifact_manifest.json` | High |
| **File Carving (Unallocated Space)** | **High (Small files)** | Original file byte remnants recoverable from unallocated clusters prior to re-allocation | Medium-High |
