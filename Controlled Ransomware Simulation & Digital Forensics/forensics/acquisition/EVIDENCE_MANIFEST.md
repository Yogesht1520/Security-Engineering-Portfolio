# Forensic Evidence Manifest & Chain of Custody
## Case: DFIR-Lab-001 — Controlled Ransomware Simulation

| Parameter | Value |
|---|---|
| **Case Identifier** | DFIR-Lab-001 |
| **Incident ID** | `B67F15E3-58BE-4DF6-8A7E-2950BD7A05F4` |
| **Lead Examiner** | Yogesh T (Lead DFIR Analyst) |
| **Target Host** | `DFIR-SimVM` (Windows 11 Enterprise x64, 24H2 Build 26100) |
| **Physical Acquisition Workstation** | Windows 11 Enterprise Host (NVMe Storage Repo `E:\ForensicEvidence\DFIR-Lab-001\`) |
| **Acquisition Date** | 2026-10-22 (IST) / 2026-10-22 (UTC) |

---

## 1. Evidence Inventory & Cryptographic Ledger

The table below documents all primary and derived forensic evidence items acquired during this investigation.

> **Offline Evidence Retention Policy:** To comply with Git repository constraints and operational DFIR standards, multi-gigabyte forensic images (`*.raw`, `*.vdi`, `*.vmdk`) are retained offline in encrypted analyst storage (`E:\ForensicEvidence\DFIR-Lab-001\`) and excluded from version control via `.gitignore`. The SHA-256 digests below represent the immutable verification baseline.

| Item ID | Description | Source / Image File | Format | File Size | Acquisition Method | Cryptographic SHA-256 Digest | Status |
|---|---|---|---|---|---|---|---|
| **EVD-001** | Primary Memory Dump | `DFIR-SimVM-memory.raw` | ELF64 Core Dump | 8,735,768,576 B (8.13 GB) | Live Hypervisor Memory Acquisition (`VBoxManage debugvm dumpvmcore`) | `198A69B7412A7FD05CD88271E7C223C8F02D03DA14D3436AE715EB2FD0D5EFD3` | Retained Offline (Verified) |
| **EVD-002** | Primary Disk Clone | `DFIR-SimVM-disk.vdi` | VirtualBox VDI | 38,375,000,064 B (35.74 GB) | Clean Power-off Clone (`VBoxManage clonemedium disk`) | `33695DE62EE72C8E3FDE8225BD7688D9CDFD656B22F1DB7EC51D08B63579B980` | Retained Offline (Verified) |
| **EVD-003** | Derived Disk Container | `DFIR-SimVM-disk.vmdk` | VMware VMDK | 38,354,026,496 B (35.72 GB) | Sector-by-Sector Container Translation (`--format VMDK`) | `98E32CEA9633D9F65AAC2A93F9236F3C31A12DD50797BF4DEB5E357D0166C219` | Retained Offline (Verified) |

---

## 2. Container Conversion Rationale & Validation Record

### Why was EVD-003 (VMDK) derived from EVD-002 (VDI)?
Autopsy 4.23.1 running on Windows does not possess native container support for VirtualBox `.vdi` format (throwing `"Error loading file systems"`). To enable The Sleuth Kit (TSK) and Autopsy to inspect the partition table and NTFS file records without modifying the guest filesystem, `VBoxManage clonemedium disk <source.vdi> <dest.vmdk> --format VMDK` was executed.

### How was filesystem content equivalence validated?
* **Container vs. Logical Disk Hashes:** Because container metadata headers and sparse block allocation descriptors differ between Oracle VDI and VMware VMDK specifications, the container-level SHA-256 hashes differ (`33695DE6...` vs `98E32CEA...`).
* **Sector-Level Translation:** `VBoxManage clonemedium` translates the virtual disk sectors without altering the inner partition geometry.
* **Partition Geometry Verification:** Partition `vol6` (NTFS Windows C: drive) starts at sector offset 444,416 with identical cluster size (4,096 bytes) and volume sector counts across both formats.
* **MFT Invariant Proof:** Content equivalence between the primary VDI clone and the derived VMDK sparse container was verified by confirming identical partition table geometry (Partition `vol6` starting at sector offset 444,416) and bitstream NTFS volume metadata, corroborated when Autopsy mounted the VMDK container and parsed identical cluster runs, Volume Serial Number, and Master File Table records.

---

## 3. Tool Version, Executable Provenance & Hashes

All tool binaries were verified with cryptographic SHA-256 digests prior to evidence analysis:

| Tool Name | Exact Release Version | Binary Executable SHA-256 Digest | Role in Evidence Handling | Execution Environment |
|---|---|---|---|---|
| **Volatility 3** | Framework 2.26.0 | `664102407BC13906AC0A401A737028334907C0E235AB9DFAAF94A301A50687B3` | Volatile Memory Forensics | Host (Win 11 x64, Python 3.13) |
| **Autopsy** | 4.23.1 (TSK 4.12.1) | `EE790ADFCF8436D7B128DDB43D6F6DF1A8404DF7612972B2BEF7022B4F27BF69` | Post-Mortem Disk & MFT Analysis | Host (Win 11 x64) |
| **VirtualBox** | 7.1.6 r167084 | `178E016ED38CB6E369A5C17C6C960C176674B9C864030D8CE0AD2867613BECFF` | Hypervisor, Memory Dump, Disk Clone | Host (Win 11 x64) |
| **PowerShell** | 7.x / 5.1 | Built-in Windows Runtime (`powershell.exe`) | Cryptographic Verification (`Get-FileHash`) | Host (Win 11 x64) |

---

## 4. Chain of Custody & Evidence Transfer Ledger

| Timestamp (IST) | Evidence Item | Action Taken | Transferring Party | Receiving Party | Storage Identifier / Location | Verification Check |
|---|---|---|---|---|---|---|
| 2026-10-22 22:40:12 | **EVD-001** | Live RAM core dump acquired via hypervisor CLI | Guest VM `DFIR-SimVM` | Analyst Yogesh T | `E:\ForensicEvidence\DFIR-Lab-001\DFIR-SimVM-memory.raw` | SHA-256 recorded: `198A69B7...` |
| 2026-10-22 22:45:00 | **EVD-002** | Target VM powered down; bitstream VDI disk cloned | Hypervisor Storage | Analyst Yogesh T | `E:\ForensicEvidence\DFIR-Lab-001\DFIR-SimVM-disk.vdi` | SHA-256 recorded: `33695DE6...` |
| 2026-10-22 23:00:15 | **EVD-003** | EVD-002 converted to VMDK container for Autopsy | Analyst Yogesh T | Analyst Yogesh T | `E:\ForensicEvidence\DFIR-Lab-001\DFIR-SimVM-disk.vmdk` | Independent SHA-256: `98E32CEA...` |
| 2026-10-23 00:30:00 | **EVD-001** | Memory analysis executed via Volatility 3 v2.26.0 | Analyst Yogesh T | Volatility Engine | Workstation In-Memory / Analysis Scratch | Re-verified hash before plugin execution |
| 2026-10-23 01:15:00 | **EVD-003** | VMDK ingested into Autopsy Case `DFIR-Lab-001` | Analyst Yogesh T | Autopsy / TSK | `E:\ForensicEvidence\DFIR-Lab-001\AutopsyCase\` | Partition vol6 mounted; MFT parsed |
| 2026-10-23 01:41:00 | Target VM | VM restored to clean pre-simulation baseline | Analyst Yogesh T | VirtualBox Hypervisor | VirtualBox VM Directory | Snapshot restored 100% verified |
