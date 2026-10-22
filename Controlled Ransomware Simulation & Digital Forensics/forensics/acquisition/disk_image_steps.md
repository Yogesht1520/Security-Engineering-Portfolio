# Disk Image Acquisition — Step-by-Step Procedure

> **Phase:** Phase 2 — Evidence Acquisition (Part 2)
> **Prerequisite:** Memory dump completed and hash recorded.
> **Order:** Always capture memory FIRST (volatile), then disk (non-volatile).

---

## Why Disk Forensics?

The disk image preserves:
- File system structure (NTFS MFT, directory entries)
- File modification/creation/access timestamps (MACE times)
- Deleted files (allocated but unlinked inodes)
- Prefetch files (execution evidence for each binary run)
- Windows Registry hives (persistence mechanisms, run keys, user activity)
- Volume Shadow Copies (or their absence, if T1490 succeeded)
- Event logs (.evtx files in C:\Windows\System32\winevt\Logs\)
- The ransom note file with its exact creation timestamp
- Renamed/encrypted files showing the mass modification event cluster

---

## Method A — FTK Imager Lite (Recommended — Free, No Installation Required)

FTK Imager Lite is the industry-standard forensic imaging tool. The "Lite" version runs
without installation (portable executable).

### Prerequisites

- Download FTK Imager Lite from AccessData/Exterro (free, no license required):
  `https://accessdata.com/product-download/ftk-imager-version-4-7-1`
- Copy to the HOST machine (do NOT copy into the VM — we image from outside)
- VM in running or cleanly powered-off state (powered-off is fine for disk imaging)

### Steps (imaging a VirtualBox VM disk from the host)

> **Note:** The cleanest approach is to power off the VM (after memory dump) and image the
> .vdi / .vmdk file directly. This avoids any write activity on the target volume.

**Step 1: Power off the VM (gracefully or force off)**
```
VirtualBox Manager > Machine > ACPI Shutdown (or Force Off)
DO NOT revert to snapshot yet — we need the post-simulation disk state.
```

**Step 2: Convert VDI to RAW (for FTK Imager compatibility)**
```cmd
# On the HOST machine:
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" clonemedium disk ^
  "C:\Users\<user>\VirtualBox VMs\DFIR-SimVM\DFIR-SimVM.vdi" ^
  "C:\dfir_evidence\disk_image_raw.img" ^
  --format RAW
```

**Step 3: Open FTK Imager Lite on the host**
```
File > Add Evidence Item > Image File
Select: C:\dfir_evidence\disk_image_raw.img
```

**Step 4: Create a forensic E01 image**
```
File > Create Disk Image
Source: the raw image you added
Destination format: E01 (Expert Witness Format) — industry standard
Image destination: C:\dfir_evidence\
Case number: DFIR-LAB-001
Evidence number: DISK-001
Examiner: Yogesh T
Notes: Post-simulation disk image of DFIR-SimVM
Enable "Verify images after they are created"
Enable "Create directory listings of all files in the image"
```

**Step 5: Record the hash from FTK Imager's verification output**

FTK Imager displays MD5 and SHA-1 hashes of the completed image. Record both:
```
MD5:  _______________________________________________
SHA1: _______________________________________________
```

---

## Method B — VBoxManage Direct Export to RAW (Simpler)

If FTK Imager is not available, the RAW image from Method A Step 2 is sufficient
for Autopsy. Autopsy accepts RAW disk images natively.

**Hash the raw image:**
```powershell
Get-FileHash "C:\dfir_evidence\disk_image_raw.img" -Algorithm SHA256 | Tee-Object -FilePath "C:\dfir_evidence\disk_image_raw.img.sha256"
```

---

## Method C — dc3dd (Open-Source, Linux/WSL)

`dc3dd` is the forensically-sound version of `dd` with integrated hashing and progress output.
Use this if you prefer a fully open-source tool or are working in a Linux environment.

```bash
# In WSL or a Linux host:
# Identify the VM disk device or mount the VDI file

# Option 1: Direct dd from block device (if VM disk is exposed as a device)
dc3dd if=/dev/sdX of=/evidence/disk_image.raw hash=sha256 hlog=/evidence/disk_image.hash log=/evidence/dc3dd.log

# Option 2: From a VDI file converted to raw first (same as Method A Step 2)
# Then:
dc3dd if=disk_image_raw.img of=disk_image_verified.raw hash=sha256 hlog=disk_hash.txt
```

---

## Acquisition Notes Template

```
DISK ACQUISITION RECORD
========================
Examiner: Yogesh T
Date/Time: _______________
VM Name: _______________
VM OS: _______________
VM Disk Type: [ ] VDI  [ ] VMDK  [ ] Other: ___
Tool Used: [ ] FTK Imager  [ ] VBoxManage RAW  [ ] dc3dd

Source Disk Path: _______________
Output Image Path: _______________
Output Format: [ ] E01  [ ] RAW  [ ] Other: ___
Image Size: _______________ bytes

Hashes:
  MD5:    _______________________________________________
  SHA-1:  _______________________________________________
  SHA-256: _______________________________________________

Pre-acquisition notes:
  - VM state when imaging began: [ ] Running  [ ] Powered Off
  - Time between memory dump and disk image: _______________
  - Any write activity on VM disk after simulation and before imaging: _______________

Chain of Custody:
  - Evidence stored at: _______________
  - Drive encrypted: [ ] YES [ ] NO
  - Storage media hash: _______________
```

---

## Importing into Autopsy

After acquiring the disk image:

1. Open Autopsy
2. Create a New Case:
   - Case Name: `DFIR-Lab-001`
   - Examiner: `Yogesh T`
3. Add a Data Source:
   - Source Type: Disk Image or VM File
   - Path: Your `.E01` or `.raw` image
4. Run Ingest Modules — enable ALL of these:
   - Recent Activity
   - Hash Lookup (MD5/SHA-256)
   - File Type Identification
   - Keyword Search
   - Email Parser
   - Extension Mismatch Detector (critical: finds `.locked` files with wrong signatures)
   - PhotoRec Carver
   - **Timeline Analysis** (most important for this investigation)
5. Wait for ingest to complete (15-60 minutes depending on disk size)
6. Then open Timeline Analysis: `Tools > Timeline`

---

## Next Step

Proceed to Phase 3:
**[volatility_analysis/ANALYSIS_NOTES.md](../volatility_analysis/ANALYSIS_NOTES.md)**
