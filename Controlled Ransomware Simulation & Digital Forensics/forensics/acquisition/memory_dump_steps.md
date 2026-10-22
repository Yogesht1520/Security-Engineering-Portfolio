# Memory Dump Acquisition — Step-by-Step Procedure

> **Phase:** Phase 2 — Evidence Acquisition (Part 1)  
> **Prerequisite:** Simulation has been executed (Phase 1 complete). VM is still running. Do NOT reboot or power off.  
> **Critical Rule:** Always capture memory FIRST (volatile), then disk (non-volatile).  
> **Evidence Manifest:** See [`forensics/acquisition/EVIDENCE_MANIFEST.md`](./EVIDENCE_MANIFEST.md) for master cryptographic hashes and chain of custody.

---

## Why Memory Forensics?

Live volatile memory contains artifacts that do not exist on disk:
- Active running processes and hidden / unlinked processes
- Open network connections and socket structures
- Decrypted strings and encryption keys in heap/stack
- Injected code, shellcode, and hollowed memory regions
- Exact command-line arguments of running and recently exited processes
- Active user session descriptors and open file handles

For ransomware DFIR, memory forensics reveals the exact process execution lineage, user account context, and proves whether outbound command-and-control communication occurred.

---

## Actual Lab Procedure Executed (VirtualBox Live Hypervisor Dump)

VirtualBox produces a full memory dump directly from the host workstation without installing software on the guest VM, preserving volatile state without contaminating guest RAM.

### Step 1: Identify Running Target VM
```cmd
# Execute on physical host workstation:
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list runningvms
```
*Identified VM: `"DFIR-SimVM"` with UUID `{206ced7c-412c-4f9a-bced-fe23d80c2212}`.*

### Step 2: Acquire Volatile RAM Core Dump
```cmd
# Live memory acquisition via hypervisor while guest remains running:
"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" debugvm "DFIR-SimVM" dumpvmcore --filename "forensics\acquisition\DFIR-SimVM-memory.raw"
```
* **Output File:** `forensics/acquisition/DFIR-SimVM-memory.raw` (`EVD-001`)
* **Format:** ELF64 Core Dump (natively parsed by Volatility 3)
* **File Size:** 8,735,768,576 bytes (8.13 GB)
* **Acquisition Timestamp:** 2026-10-22 22:40:12 IST (17:10:12 UTC)

---

## Cryptographic Verification

Generate the immutable verification digest immediately after acquisition:

```powershell
Get-FileHash "forensics\acquisition\DFIR-SimVM-memory.raw" -Algorithm SHA256
```

**Recorded Verification Hash:**
```text
Algorithm : SHA256
Hash      : 198A69B7412A7FD05CD88271E7C223C8F02D03DA14D3436AE715EB2FD0D5EFD3
Path      : forensics\acquisition\DFIR-SimVM-memory.raw
```
*Tracked in: `forensics/acquisition/DFIR-SimVM-memory.raw.sha256`*

---

## Analysis Hand-off to Volatility 3

Once acquired and verified, proceed to **Phase 3: Volatile Memory Forensics**:
```powershell
# Analyze with Volatility 3 Framework 2.28.2:
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.info
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.pslist
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.pstree
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.cmdline
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.netscan
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.malfind
```
*Analysis documentation: **[`forensics/volatility_analysis/ANALYSIS_NOTES.md`](../volatility_analysis/ANALYSIS_NOTES.md)**.*

---

## Offline Evidence Retention Policy

In compliance with repository constraints and DFIR operational security, the 8.13 GB memory capture (`DFIR-SimVM-memory.raw`) is retained offline on encrypted analyst storage and excluded from Git via `.gitignore`.
