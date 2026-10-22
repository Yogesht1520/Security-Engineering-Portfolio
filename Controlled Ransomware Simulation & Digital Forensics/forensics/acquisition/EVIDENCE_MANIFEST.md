# Forensic Evidence Manifest & Chain of Custody
## Case: DFIR-Lab-001 — Controlled Ransomware Simulation

| Parameter | Value |
|---|---|
| **Case Identifier** | DFIR-Lab-001 |
| **Incident ID** | `B67F15E3-58BE-4DF6-8A7E-2950BD7A05F4` |
| **Lead Examiner** | Yogesh T (Lead DFIR Analyst) |
| **Target Host** | `DFIR-SimVM` (Windows 11 Enterprise x64, 24H2 Build 26100) |
| **Acquisition Host** | Windows 11 Physical Forensic Workstation |
| **Acquisition Date** | 2026-10-22 (IST) / 2026-10-22 (UTC) |

---

## 1. Evidence Inventory & Cryptographic Ledger

The following table documents all primary and derived forensic evidence items acquired during this investigation. 

> **Offline Retention Notice:** In accordance with DFIR standards and repository constraints, large forensic images (multi-gigabyte `.raw`, `.vdi`, and `.vmdk` files) are stored securely on local encrypted analyst storage and are excluded from Git version control via `.gitignore`. The cryptographic SHA-256 hashes below represent the immutable verification baseline.

| Item ID | Description | Source / Image File | Format | File Size | Acquisition Method | Cryptographic SHA-256 Digest | Status |
|---|---|---|---|---|---|---|---|
| **EVD-001** | Primary Memory Dump | `DFIR-SimVM-memory.raw` | ELF64 Core Dump | 8,735,768,576 B (8.13 GB) | Hypervisor Live Freeze (`VBoxManage debugvm dumpvmcore`) | `198A69B7412A7FD05CD88271E7C223C8F02D03DA14D3436AE715EB2FD0D5EFD3` | Retained Offline (Verified) |
| **EVD-002** | Primary Disk Image | `DFIR-SimVM-disk.vdi` | VirtualBox VDI | 38,375,000,064 B (35.74 GB) | Clean Power-off Clone (`VBoxManage clonemedium disk`) | `33695DE62EE72C8E3FDE8225BD7688D9CDFD656B22F1DB7EC51D08B63579B980` | Retained Offline (Verified) |
| **EVD-003** | Derived Disk Image | `DFIR-SimVM-disk.vmdk` | VMware VMDK | 38,354,026,496 B (35.72 GB) | Bitstream Container Conversion (`VBoxManage clonemedium disk --format VMDK`) | `98E32CEA9633D9F65AAC2A93F9236F3C31A12DD50797BF4DEB5E357D0166C219` | Retained Offline (Verified) |

---

## 2. Evidence Derivation & Conversion Rationale

* **Why is EVD-003 (VMDK) derived from EVD-002 (VDI)?**
  * Autopsy 4.23.1 running on Windows does not possess native container support for VirtualBox `.vdi` format (yielding `"Error loading file systems"`).
  * To enable The Sleuth Kit (TSK) and Autopsy to parse the partition table and NTFS Master File Table without altering the evidence data, `VBoxManage clonemedium` was executed to convert the container to VMware VMDK format.
  * Because container structures differ between VDI and VMDK, their container-level SHA-256 hashes are distinct (`33695DE6...` vs `98E32CEA...`). The underlying NTFS partition filesystem contents remained bitstream-identical.

---

## 3. Tool Version & Provenance

| Tool Name | Version | Role in Evidence Handling | Execution Environment |
|---|---|---|---|
| **VirtualBox** | 7.1.6 r167084 | Hypervisor, Memory Dump, and Disk Cloning | Windows 11 Host |
| **PowerShell** | 7.x / 5.1 | `Get-FileHash` Cryptographic Verification | Windows 11 Host |
| **Volatility 3** | Framework 2.26.0 | Volatile Memory Analysis | Python 3.13 Host |
| **Autopsy** | 4.23.1 (TSK 4.12.1) | Post-Mortem Disk & MFT Analysis | Windows 11 Host |

---

## 4. Chain of Custody Log

| Date & Time (IST) | Evidence ID | Action Taken | Performed By | Verification Method |
|---|---|---|---|---|
| 2026-10-22 22:40:12 | **EVD-001** | Live memory dump captured from running VM `DFIR-SimVM` | Yogesh T | SHA-256 calculated immediately post-capture |
| 2026-10-22 22:45:00 | **EVD-002** | VM cleanly powered off; VDI base disk cloned to workstation | Yogesh T | SHA-256 calculated immediately post-clone |
| 2026-10-22 23:00:15 | **EVD-003** | Converted EVD-002 from VDI to VMDK for Autopsy ingest | Yogesh T | Independent SHA-256 calculated on VMDK |
| 2026-10-23 00:30:00 | **EVD-001** | Memory analysis executed via Volatility 3 v2.26.0 | Yogesh T | Verified hash matches acquisition log |
| 2026-10-23 01:15:00 | **EVD-003** | Ingested VMDK into Autopsy 4.23.1 Case `DFIR-Lab-001` | Yogesh T | Verified volume vol6 NTFS MFT structures |
| 2026-10-23 01:41:00 | Target VM | VM `DFIR-SimVM` restored to clean baseline snapshot | Yogesh T | VirtualBox snapshot manager verified 100% |
