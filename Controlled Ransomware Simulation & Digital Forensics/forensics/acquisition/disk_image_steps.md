# Disk Image Acquisition — Step-by-Step Procedure

> **Phase:** Phase 2 — Evidence Acquisition (Part 2)  
> **Prerequisite:** Memory dump completed and hash recorded.  
> **Order:** Always capture memory FIRST (volatile), then disk (non-volatile).  
> **Evidence Manifest:** See [`forensics/acquisition/EVIDENCE_MANIFEST.md`](./EVIDENCE_MANIFEST.md) for master cryptographic hashes and chain of custody.

---

## Why Disk Forensics?

The disk image preserves:
- File system structure (NTFS MFT, directory records)
- File modification/creation/access timestamps (MACE times)
- Deleted files (allocated but unlinked clusters)
- Prefetch files (execution evidence for each binary run)
- Windows Registry hives (persistence mechanisms, run keys, user activity)
- Volume Shadow Copies (or absence if T1490 executed)
- Windows Event logs (`.evtx` files in `C:\Windows\System32\winevt\Logs\`)
- The ransom note file with its exact creation timestamp
- Renamed/encrypted files showing the mass modification event cluster

---

## Actual Lab Procedure Executed (VirtualBox Host-Level Clone)

In this investigation, disk acquisition was conducted from the host workstation after the target VM was cleanly powered down, ensuring zero post-simulation disk writes occurred on the target volume.

### Step 1: Clean VM Power Off
```powershell
# Initiate ACPI power off via VirtualBox hypervisor
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "DFIR-SimVM" acpipowerbutton
```
*Note: Do NOT revert to snapshot yet — we require the post-simulation disk state.*

### Step 2: Primary Bitstream Disk Clone (`.vdi`)
```powershell
# Clone the virtual disk medium directly from host storage
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" clonemedium disk ^
  "C:\Users\yoges\VirtualBox VMs\DFIR-SimVM\DFIR-SimVM.vdi" ^
  "forensics\acquisition\DFIR-SimVM-disk.vdi" ^
  --format VDI
```
* **Output File:** `forensics/acquisition/DFIR-SimVM-disk.vdi` (`EVD-002`)
* **File Size:** 38,375,000,064 bytes (35.74 GB)
* **SHA-256 Digest:** `33695DE62EE72C8E3FDE8225BD7688D9CDFD656B22F1DB7EC51D08B63579B980`

### Step 3: Container Conversion for Autopsy Compatibility (`.vmdk`)
Autopsy running on Windows does not possess native container support for VirtualBox `.vdi` files (yielding `"Error loading file systems"`). To allow The Sleuth Kit (TSK) to parse the NTFS file system, the cloned disk was converted to a VMware VMDK container:

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" clonemedium disk ^
  "forensics\acquisition\DFIR-SimVM-disk.vdi" ^
  "forensics\acquisition\DFIR-SimVM-disk.vmdk" ^
  --format VMDK
```
* **Output File:** `forensics/acquisition/DFIR-SimVM-disk.vmdk` (`EVD-003`)
* **File Size:** 38,354,026,496 bytes (35.72 GB)
* **Independent SHA-256 Digest:** `98E32CEA9633D9F65AAC2A93F9236F3C31A12DD50797BF4DEB5E357D0166C219`

---

## Cryptographic Verification

Calculate and verify SHA-256 hashes immediately upon acquisition:

```powershell
Get-FileHash "forensics\acquisition\DFIR-SimVM-disk.vdi" -Algorithm SHA256
Get-FileHash "forensics\acquisition\DFIR-SimVM-disk.vmdk" -Algorithm SHA256
```

---

## Importing into Autopsy

1. Launch Autopsy (Version 4.23.1).
2. Create New Case:
   - Case Name: `DFIR-Lab-001`
   - Case Number: `2026-001`
   - Examiner: `Yogesh T`
3. Add Data Source:
   - Source Type: **Disk Image or VM File**
   - Path: `forensics\acquisition\DFIR-SimVM-disk.vmdk`
   - Sector Size: 512 bytes (default auto-detect)
4. Configure Ingest Modules:
   - File Type Identification
   - Extension Mismatch Detector (flags `.locked` files with altered magic numbers / signatures)
   - Recent Activity
   - Hash Lookup
5. Timeline Analysis:
   - Open `Tools > Timeline`
   - Filter to hour window 22:00 IST to visualize the 4-second encryption storm.
   - Export MFT listing via Table View -> `Save Table as CSV` -> `directory_mft_listing.csv`.

---

## Offline Evidence Retention Policy

In compliance with repository constraints and DFIR operational security, multi-gigabyte disk images (`*.vdi`, `*.vmdk`) are retained offline on the analyst workstation and excluded from version control via `.gitignore`.
