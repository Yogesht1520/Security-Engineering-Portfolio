# Atomic Red Team Test Plan
# Ransomware Behavior Simulation — MITRE ATT&CK Mapped

> **Scope Notice:** **REFERENCE-ONLY TEST PROCEDURE PLAN**  
> **Reference Repository:** https://github.com/redcanaryco/atomic-red-team  
>
> ### Execution Scope & Test Exclusion Status for Primary Run (Run ID `B67F15E3`)
> The primary investigation documented in this repository (`DFIR-Lab-001`) was driven **exclusively** by the purpose-built script [`simulation/custom_behavior_sim.py`](./custom_behavior_sim.py) to maintain a deterministic, tightly bounded single-script telemetry baseline. 
>
> The Atomic Red Team test procedures defined in this document serve as **technical benchmark specifications** for future expansion and were **NOT executed** during the primary forensic capture.
>
> | Atomic Test ID | Technique Name | Planned Command / Tool | Status in Run `B67F15E3` | Reason for Exclusion / Alternative Used |
> |---|---|---|---|---|
> | **T1490 #1** | Inhibit System Recovery: Shadow Deletion | `vssadmin.exe delete shadows /all /quiet` | ❌ **EXCLUDED** | Evaluated via simulated log mode in `custom_behavior_sim.py` |
> | **T1490 #2** | Inhibit System Recovery: Disable WinRE | `bcdedit.exe /set {default} recoveryenabled No` | ❌ **EXCLUDED** | Excluded to prevent VM unbootability; evaluated in safe log mode |
> | **T1486 #1** | Data Encrypted for Impact | `cipher.exe` / batch file encryption | ❌ **EXCLUDED** | Replaced by deterministic XOR loop in `custom_behavior_sim.py` |
> | **Manual** | Ransom Note Drop via PowerShell | PowerShell `Set-Content` script | ❌ **EXCLUDED** | Replaced by python file drop (`READ_ME_RECOVER.txt`) |
> | **T1003.001** | OS Credential Dumping: LSASS | `Invoke-AtomicTest T1003.001 -TestNumbers 1` | ❌ **EXCLUDED** | Excluded; no credential dumping performed in primary scope |

---

## Overview

This document provides reference Atomic Red Team test definitions mapped to ransomware-adjacent MITRE ATT&CK techniques. It outlines how individual command invocations produce specific forensic observables for threat hunting and detection engineering.

The procedures below are cataloged for reference, comparative analysis, and follow-up lab iterations.

---

## Pre-Execution Checklist

- [ ] VM network adapter confirmed "Not Attached" (screenshot saved)
- [ ] Clean baseline snapshot taken and named: `baseline-clean-<date>`
- [ ] Atomic Red Team installed on VM (`IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics`)
  - **Note:** This installation step requires a one-time internet connection BEFORE the network adapter is disabled. Install it while the VM still has internet, THEN disable the network adapter, THEN take the baseline snapshot. Alternatively, download Atomic Red Team manually from a separate machine, copy it in via a shared folder or ISO, then disable the network.
- [ ] PowerShell execution policy set: `Set-ExecutionPolicy Bypass -Scope Process`
- [ ] Running as Administrator inside the VM

---

## Test Sequence

### Step 1 — T1490: Inhibit System Recovery (Shadow Copy Deletion)

**Why first:** This is typically one of the first actions real ransomware takes — disabling recovery
before encryption begins. Running it first creates an early timestamp in our forensic timeline.

```powershell
# Atomic Red Team test T1490, Test #1: Delete Volume Shadow Copies via VssAdmin
Invoke-AtomicTest T1490 -TestNumbers 1

# What this does:
# Executes: vssadmin.exe delete shadows /all /quiet
# This is the exact command used by WannaCry, Ryuk, LockBit, etc.
# On a VM without actual shadow copies, it will "fail gracefully" but the
# PROCESS EVENT (cmd.exe -> vssadmin.exe) is still created in the event log
# and in memory — which is exactly what we want for forensic analysis.
```

**Expected forensic artifact:** `vssadmin.exe` spawned as a child of `cmd.exe` or `powershell.exe`,
visible in Volatility `pslist`/`pstree` and Windows Event Log (Event ID 4688 - Process Creation).

---

### Step 2 — T1490: Inhibit System Recovery (Disable Windows Recovery)

```powershell
# Atomic Red Team test T1490, Test #2: Disable Windows Recovery Environment
Invoke-AtomicTest T1490 -TestNumbers 2

# What this does:
# Executes: bcdedit /set {default} recoveryenabled No
# Disables Windows Recovery Environment boot option
# Reversible: bcdedit /set {default} recoveryenabled Yes
```

**Expected forensic artifact:** `bcdedit.exe` process creation event; registry change to BCD store.

---

### Step 3 — T1486: Data Encrypted for Impact (File Encryption Simulation)

```powershell
# Atomic Red Team test T1486, Test #1: Encrypt files using cipher.exe
Invoke-AtomicTest T1486 -TestNumbers 1

# What this does:
# Creates a test directory with sample files, then uses built-in cipher.exe
# to overwrite free space / simulate file modification.
# Alternatively uses copy with renamed extensions.
```

**Expected forensic artifact:** File system timeline showing rapid file modification events in
a short time window — the hallmark of encryption activity visible in Autopsy timeline analysis.

---

### Step 4 — Manual Ransom Note Drop (Custom, Fully Controlled)

After the Atomic tests, manually create the ransom note to simulate the final ransomware action:

```powershell
# Create a test directory to contain all simulation artifacts
$testDir = "C:\Users\Public\test_ransomware_sim"
New-Item -ItemType Directory -Force -Path $testDir

# Drop the fake ransom note
$ransomNote = @"
YOUR FILES HAVE BEEN ENCRYPTED

[SIMULATION - FOR FORENSIC TRAINING ONLY - NOT REAL]

All your important files are encrypted.
To recover your files, you must follow these instructions:

1. Send 0.5 BTC to wallet: [SIMULATED_WALLET_ADDRESS]
2. Email proof of payment to: [SIMULATED_EMAIL]
3. You have 72 hours before the key is destroyed.

DO NOT attempt to decrypt files yourself.
DO NOT restart your computer.
DO NOT contact law enforcement.

[THIS IS A CONTROLLED SIMULATION. NO FILES WERE ACTUALLY HARMED.]
"@

$ransomNote | Set-Content -Path "$testDir\README_YOUR_FILES.txt" -Encoding UTF8
Write-Host "Ransom note dropped at: $testDir\README_YOUR_FILES.txt"
```

**Expected forensic artifact:** The ransom note file visible in Autopsy file browser with a precise
creation timestamp, anchoring the end of the "attack" in the forensic timeline.

---

### Step 5 — T1003: OS Credential Dumping (Optional — LSASS Memory Read Attempt)

```powershell
# Atomic Red Team test T1003.001: LSASS Memory - ProcDump
# Only run this if you intend to analyze credential-dumping artifacts in Volatility
Invoke-AtomicTest T1003.001 -TestNumbers 1

# What this does:
# Attempts to dump LSASS memory using SysInternals ProcDump or Task Manager method
# Even if the dump fails (e.g., due to missing ProcDump), the *access attempt*
# creates artifacts: handle opens to lsass.exe visible in memory forensics
```

**Expected forensic artifact:** Suspicious process accessing `lsass.exe` visible via Volatility
`handles` and `dlllist` plugins; potential `malfind` hits.

---

## Post-Execution — State Capture

**IMMEDIATELY after running all tests**, before any cleanup or reboot:

1. **Do NOT restart the VM** — memory state must be preserved for capture
2. Follow `forensics/acquisition/memory_dump_steps.md` to capture the memory dump
3. Then follow `forensics/acquisition/disk_image_steps.md` for the disk image
4. Only then may you revert the VM to the baseline snapshot

---

## Cleanup / Reversal Commands

If you need to undo the Atomic tests manually (e.g., before taking the final disk image):

```powershell
# Re-enable Windows Recovery
bcdedit /set {default} recoveryenabled Yes

# Re-enable shadow copies (create a new one)
vssadmin create shadow /for=C:

# Remove test directory
Remove-Item -Recurse -Force "C:\Users\Public\test_ransomware_sim"
```

> **Note:** For the forensic exercise, do NOT run cleanup before capturing the memory dump and disk image.
> The artifacts are what we want to find. Cleanup happens AFTER evidence acquisition.

---

## Evidence Mapping Summary (Reference Specification)

| Test ID | MITRE Technique | Planned Memory Observable | Planned Disk Observable | Run `B67F15E3` Status |
|---|---|---|---|---|
| **T1490 #1** | Shadow Copy Deletion | `vssadmin.exe` in pslist/pstree, Event 4688 | Prefetch file for vssadmin.exe | ❌ Excluded (Simulated log mode) |
| **T1490 #2** | Recovery Disable | `bcdedit.exe` in pslist, cmd args in cmdline | BCD registry hive change | ❌ Excluded (Simulated log mode) |
| **T1486 #1** | File Encryption Sim | Script process in pslist | Mass file modification timestamps in timeline | ❌ Excluded (Custom Python XOR used) |
| **Manual** | Ransom Note Drop | PowerShell args in cmdline | Ransom note file with precise creation time | ❌ Excluded (Python file drop used) |
| **T1003.001** | LSASS Dump Attempt | lsass.exe handle access, malfind | ProcDump binary (if used), lsass.dmp | ❌ Excluded (Out of scope) |
