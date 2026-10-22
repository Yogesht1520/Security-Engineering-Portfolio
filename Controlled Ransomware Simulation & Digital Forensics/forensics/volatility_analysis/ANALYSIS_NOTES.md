# Volatility 3 — Memory Forensics Analysis Notes
# Phase 3 — Blind Investigation

> **Investigator:** Yogesh T (Lead DFIR Analyst)  
> **Evidence File:** `forensics/acquisition/DFIR-SimVM-memory.raw`  
> **Evidence SHA-256:** `198A69B7412A7FD05CD88271E7C223C8F02D03DA14D3436AE715EB2FD0D5EFD3`  
> **Analysis Date:** 2026-10-22  
> **Tool:** Volatility 3 (Framework v2.28.2)  
>
> **BLIND INVESTIGATION PROTOCOL:** Reconstructed attack timeline, processes, command lines, and network posture purely from memory structures without prior assumption.

---

## Environment & Tooling Setup

- Volatility 3 v2.28.2 installed on host forensic workstation.
- Symbol Table: `ntkrnlmp.pdb/C29EBFB06B78B3C020DCA66D99713F9E-1.json.xz` (Windows 11 24H2 symbols automatically resolved).

---

## Step 1 — Identify Operating System (`windows.info`)

**Command:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.info
```

**Output recorded in:** [`windows_info_output.txt`](./windows_info_output.txt)

**Key Forensic Parameters:**
| Parameter | Value |
|---|---|
| **OS Version** | Windows 11 Enterprise (64-bit) |
| **Major / Minor Build** | 15.26100 (Windows 11 24H2 Build 26100) |
| **Kernel Base** | `0xf8037fa00000` |
| **DTB (Directory Table Base)** | `0x1ae000` |
| **System Time at Capture** | `2026-10-22 17:09:14 UTC` |
| **Number of Processors** | 2 |

---

## Step 2 — Active Process Enumeration (`windows.pslist`)

**Command:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.pslist > pslist_output.txt
```

**Output recorded in:** [`pslist_output.txt`](./pslist_output.txt)

**Notable Processes Identified:**
| PID | PPID | ImageFileName | Create Time (UTC) | Forensic Significance |
|---|---|---|---|---|
| **4500** | 4348 | `explorer.exe` | 2026-10-21 19:01:36 | Primary interactive user desktop shell |
| **2428** | 4500 | `powershell.exe` | 2026-10-22 11:35:00 | Interactive console window session |
| **7260** | 2428 | `conhost.exe` | 2026-10-22 11:35:00 | Console host attached to PowerShell session |
| **4704** | 4500 | `powershell.exe` | 2026-10-22 11:36:56 | Second interactive terminal session |
| **1948** | 4704 | `conhost.exe` | 2026-10-22 11:36:56 | Console host for second PowerShell terminal |
| **6312** | 7892 | `Notepad.exe` | 2026-10-22 11:29:42 | Active text editor session inspecting script/ransom artifacts |
| **3124** | 820 | `MsMpEng.exe` | 2026-10-21 19:01:30 | Windows Defender Antivirus engine |

---

## Step 3 — Process Hierarchy & Tree (`windows.pstree`)

**Command:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.pstree > pstree_output.txt
```

**Output recorded in:** [`pstree_output.txt`](./pstree_output.txt)

**Observed Execution Chain:**
```text
explorer.exe (PID 4500)
  ├── powershell.exe (PID 2428)
  │     └── conhost.exe (PID 7260)
  ├── powershell.exe (PID 4704)
  │     └── conhost.exe (PID 1948)
  └── SnippingTool.exe (PID 2616) — Captured evidence screenshots
```

---

## Step 4 — Command Line Reconstruction (`windows.cmdline`)

**Command:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.cmdline > cmdline_output.txt
```

**Output recorded in:** [`cmdline_output.txt`](./cmdline_output.txt)

**Key Findings:**
1. **Notepad Session Inspection (PID 6312):**
   - Command line:
     ```text
     "C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe" /SESSION:...
     ```
   - Decoded session payload (UTF-16LE inside base64 session descriptor):
     `C:\Users\Public\custom_behavior_sim.py`
   - Proves the simulation script source was accessed directly in the target environment.
2. **Interactive PowerShell Sessions (PID 2428 & 4704):**
   - Both shells ran under user context `SimUser`.

---

## Step 5 — Network Sockets & Sockets Scanning (`windows.netscan`)

**Command:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.netscan > netscan_output.txt
```

**Output recorded in:** [`netscan_output.txt`](./netscan_output.txt)

**Findings:**
- **Active Sockets:** `0`
- **Listening Ports:** `0`
- **Foreign / Remote Endpoints:** `0`

**Forensic Evaluation:**
- Conclusive proof of strict network isolation (air-gap) at memory acquisition time.
- Validates that the ransomware behavior did not attempt external C2 beaconing, DNS exfiltration, or secondary payload downloads.

---

## Step 6 — Injected Code & Memory Protections (`windows.malfind`)

**Command:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.malfind > malfind_output.txt
```

**Output recorded in:** [`malfind_output.txt`](./malfind_output.txt)

**Evaluation of Findings:**
- Hits detected in:
  - `MsMpEng.exe` (PID 3124) — Microsoft Defender dynamic JIT signature evaluation buffers.
  - `TextInputHost.exe` (PID 5652) — Windows XAML input subsystem JIT compiler.
  - `powershell.exe` (PID 2428) — .NET CLR runtime JIT engine.
- **Negative Finding (Crucial):** Zero instances of unbacked PE headers (`MZ` / `PE\0\0`), shellcode stagers, or hollowed processes were detected in userland or system processes.
- **Conclusion:** The ransomware simulation operated strictly as a clean, userland process execution without rootkit hooks or in-memory process hollowing.

---

## Phase 3 Summary & Evidence Hand-off to Phase 4

| Forensic Question | Volatility 3 Answer | Corroborating Evidence |
|---|---|---|
| **What malware / script was executed?** | `custom_behavior_sim.py` | Notepad session descriptor + PowerShell process trees |
| **Where was it executed from?** | `C:\Users\Public\` | Command line session data |
| **Did it communicate over network?** | **NO** | `netscan` reported 0 open sockets or remote connections |
| **Did it inject code into system processes?** | **NO** | `malfind` found only legitimate JIT buffers (Defender, .NET) |
| **What active user artifacts remain?** | Interactive PowerShell shells + Notepad session | PIDs 2428, 4704, 6312 |

---

## Next Step

Proceed to **Phase 4: Disk Analysis with Autopsy** using the cloned disk image:
- Evidence Image: [`forensics/acquisition/DFIR-SimVM-disk.vdi`](../acquisition/DFIR-SimVM-disk.vdi)
- Autopsy analysis guide: **[forensics/autopsy_analysis/ANALYSIS_NOTES.md](../autopsy_analysis/ANALYSIS_NOTES.md)**
