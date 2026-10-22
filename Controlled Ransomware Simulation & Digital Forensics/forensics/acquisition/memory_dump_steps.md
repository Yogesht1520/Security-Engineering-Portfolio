# Memory Dump Acquisition — Step-by-Step Procedure

> **Phase:** Phase 2 — Evidence Acquisition
> **Prerequisite:** Simulation has been executed (Phase 1 complete). VM is still running. Do NOT reboot.
> **Critical:** Capture memory BEFORE disk image. Memory is volatile and will be lost on reboot.

---

## Why Memory Forensics?

Live memory contains artifacts that do not exist on disk:
- Running processes (including those that have deleted their own disk binaries)
- Open network connections
- Decrypted strings and keys
- Process injection artifacts (shellcode in legitimate process memory regions)
- Command-line arguments of running/recently-run processes
- Loaded DLLs and their in-memory locations

For ransomware DFIR, memory forensics can reveal the process tree showing how the "malware"
was launched, what commands it executed, and what other processes it interacted with.

---

## Method A — VirtualBox Built-In Memory Dump (Recommended for VirtualBox)

VirtualBox can produce a full memory dump directly from the host without installing anything
on the guest VM. This is the cleanest approach.

### Prerequisites
- VirtualBox installed on the host
- VM must be in a **running** state (not paused, not powered off)
- VM name/UUID noted (visible in VirtualBox Manager)

### Steps

**Step 1: Find your VM name**
```cmd
# On the HOST machine (not inside the VM):
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list runningvms
```
Note the VM name in quotes, e.g.: `"DFIR-SimVM"` with UUID `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`

**Step 2: Create the memory dump**
```cmd
# On the HOST machine:
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" debugvm "DFIR-SimVM" dumpvmcore --filename "C:\dfir_evidence\memory_dump.elf"
```

> **Note:** VirtualBox produces an ELF core dump format. Volatility 3 supports this natively.

**Step 3: Alternative — dump to raw format**
```cmd
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" debugvm "DFIR-SimVM" dumpvmcore --filename "C:\dfir_evidence\memory_dump.raw"
```

**Step 4: Verify the dump**
```powershell
# Check file size (should match VM's RAM allocation)
Get-Item "C:\dfir_evidence\memory_dump.elf" | Select-Object Name, Length
```

**Step 5: Hash the dump (chain of custody)**
```powershell
# Compute SHA-256 hash before analysis (evidence integrity)
Get-FileHash "C:\dfir_evidence\memory_dump.elf" -Algorithm SHA256 | Tee-Object -FilePath "C:\dfir_evidence\memory_dump.elf.sha256"
```

Record the hash: `___________________________________________________`

---

## Method B — WinPmem (Inside the Guest VM — Windows Target)

WinPmem is a free, open-source memory acquisition tool for Windows that runs inside the VM.

> **Warning:** Copying WinPmem into the VM via shared folder will add artifacts to the memory.
> Note the filename and copy time in your acquisition notes. This is a known, documented artifact.

### Steps

**Step 1: Download WinPmem (do this BEFORE disabling the VM's network)**
```
Download from: https://github.com/Velocidex/WinPmem/releases
File: winpmem_mini_x64_rc2.exe (or current release)
```
Copy the binary into the VM via VirtualBox shared folder or drag-and-drop, then disable the
network adapter before running the simulation.

**Step 2: Inside the VM — Run WinPmem as Administrator**
```cmd
# In CMD as Administrator inside the VM:
winpmem_mini_x64_rc2.exe --output memory_dump.raw --format raw
```

**Step 3: Export the dump to the host**
Copy `memory_dump.raw` from the VM to the host via VirtualBox shared folder.

**Step 4: Hash for integrity**
```powershell
# On the host:
Get-FileHash "C:\dfir_evidence\memory_dump.raw" -Algorithm SHA256
```

---

## Method C — VMware Workstation (If Using VMware)

VMware Workstation automatically creates `.vmem` files alongside the VM's vmdk files.
These can be used directly with Volatility.

**Location:** `<VM_Directory>\<VMName>.vmem`

Additionally, VMware creates a `.vmsn` snapshot file which contains memory state when a
snapshot is taken. Taking a snapshot at the "compromised" state preserves memory automatically.

```
Steps:
1. With VM running in compromised state, take a snapshot: VM > Snapshot > Take Snapshot
2. Name it: "POST-SIM-COMPROMISED-STATE-<date>"
3. The .vmem file in the VM directory IS the memory dump
4. Hash it: Get-FileHash "<path>\<VMName>.vmem" -Algorithm SHA256
```

---

## Acquisition Notes Template

Fill this out immediately after acquisition:

```
MEMORY ACQUISITION RECORD
==========================
Examiner: Yogesh T
Date/Time: _______________
VM Name: _______________
VM OS: _______________
VM RAM: _______________ GB
Method Used: [ ] VBoxManage  [ ] WinPmem  [ ] VMware .vmem

Output File: _______________
File Size: _______________ bytes
SHA-256 Hash: _______________

Pre-acquisition state notes:
  - VM uptime since simulation: _______________
  - Was VM rebooted after simulation? [ ] YES (bad) [ ] NO (good)
  - Any tools run inside VM after simulation (adds artifacts): _______________

Chain of Custody:
  - Evidence stored at: _______________
  - Drive encrypted: [ ] YES [ ] NO
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| VBoxManage says VM not running | VM must be in running state, not paused |
| Dump file is 0 bytes | Insufficient disk space or permissions on host |
| Volatility cannot parse dump | Try `--single-location` flag; check Volatility profile detection |
| WinPmem says "access denied" | Must be run as Administrator |
| WinPmem flags AV | Temporarily disable AV inside the VM (not on host), or use VBoxManage method instead |

---

## Next Step

After memory acquisition is complete and hash recorded, proceed to:
**[disk_image_steps.md](./disk_image_steps.md)**
