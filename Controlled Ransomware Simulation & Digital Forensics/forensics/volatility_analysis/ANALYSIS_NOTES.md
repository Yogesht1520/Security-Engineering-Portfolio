# Volatility 3 — Memory Forensics Analysis Notes
# Phase 3 — Independent Memory Examination

> **Investigator:** Yogesh T (Lead DFIR Analyst)  
> **Evidence Item:** `EVD-001` (`forensics/acquisition/DFIR-SimVM-memory.raw`)  
> **Evidence SHA-256:** `198A69B7412A7FD05CD88271E7C223C8F02D03DA14D3436AE715EB2FD0D5EFD3`  
> **Analysis Date:** 2026-10-22  
> **Tool:** Volatility 3 (Framework 2.28.2)  
>
> **INVESTIGATION METHODOLOGY:** Attack timeline, processes, command lines, and network posture were evaluated from volatile memory structures following a structured forensic approach, and subsequently correlated with filesystem artifacts and simulation execution records for verification.

---

## Tooling & Analysis Environment

| Tool Parameter | Value | Notes |
|---|---|---|
| **Framework Version** | Volatility 3 Framework 2.28.2 | Standalone binary (SHA-256: `664102407BC13906AC0A401A737028334907C0E235AB9DFAAF94A301A50687B3`) / Python 3.13 runtime |
| **Analysis Host OS** | Windows 11 Enterprise (64-bit) | Workstation forensic environment |
| **Symbol Table** | `ntkrnlmp.pdb/C29EBFB06B78B3C020DCA66D99713F9E-1.json.xz` | Windows 11 24H2 Build 26100 kernel symbols |
| **Evidence Path** | `forensics/acquisition/DFIR-SimVM-memory.raw` | 8.13 GB ELF64 Hypervisor Core Dump |

---

## Step 1 — Identify Operating System (`windows.info`)

**Command Executed:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.info
```

**Raw Output:** [`windows_info_output.txt`](./windows_info_output.txt)

**Key Forensic Parameters Recovered:**
| Parameter | Value |
|---|---|
| **OS Version** | Windows 11 Enterprise (64-bit) |
| **Major / Minor Build** | 15.26100 (Windows 11 24H2 Build 26100) |
| **Kernel Base** | `0xf8037fa00000` |
| **DTB (Directory Table Base)** | `0x1ae000` |
| **System Time at Capture** | `2026-10-22 17:09:14 UTC` (22:39:14 IST) |
| **Number of Processors** | 2 |

---

## Step 2 — Active Process Enumeration (`windows.pslist`)

**Command Executed:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.pslist > pslist_output.txt
```

**Raw Output:** [`pslist_output.txt`](./pslist_output.txt)

**Notable Processes Identified (Categorized by Origin):**

*A. Analyst Administrative & Diagnostic Artifacts:*
| PID | PPID | ImageFileName | Create Time (UTC) | Role / Attribution |
|---|---|---|---|---|
| **4500** | 4348 | `explorer.exe` | 2026-10-21 19:01:36 | Primary interactive desktop session (`SimUser`) |
| **2428** | 4500 | `powershell.exe` | 2026-10-22 11:35:00 | Analyst interactive shell used for staging & pre-simulation verification |
| **7260** | 2428 | `conhost.exe` | 2026-10-22 11:35:00 | Console host attached to PowerShell session (PID 2428) |
| **4704** | 4500 | `powershell.exe` | 2026-10-22 11:36:56 | Analyst interactive shell used to trigger simulation run & monitor execution |
| **1948** | 4704 | `conhost.exe` | 2026-10-22 11:36:56 | Console host attached to PowerShell session (PID 4704) |
| **6312** | 7892 | `Notepad.exe` | 2026-10-22 11:29:42 | Analyst text inspection session reviewing script configuration |
| **2616** | 4500 | `SnippingTool.exe` | 2026-10-22 06:46:03 | Analyst screen capture utility preserving visual verification evidence |

*B. Background Operating System & Defensive Services:*
| PID | PPID | ImageFileName | Create Time (UTC) | Role / Attribution |
|---|---|---|---|---|
| **3124** | 820 | `MsMpEng.exe` | 2026-10-21 19:01:30 | Microsoft Defender Antivirus real-time core protection engine |

*C. Simulated Threat Actor Activity (Ephemeral):*
| PID | PPID | ImageFileName | Execution Window | Role / Attribution |
|---|---|---|---|---|
| — | 4704 | `python.exe` | 22:26:48 – 22:26:55 IST | Rapid ephemeral process (Run ID `B67F15E3`); terminated prior to memory acquisition |

---

## Step 3 — Process Hierarchy & Tree (`windows.pstree`)

**Command Executed:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.pstree > pstree_output.txt
```

**Raw Output:** [`pstree_output.txt`](./pstree_output.txt)

**Observed Execution Chain:**
```text
explorer.exe (PID 4500)
  ├── powershell.exe (PID 2428) [Analyst Terminal 1]
  │     └── conhost.exe (PID 7260)
  ├── powershell.exe (PID 4704) [Analyst Terminal 2: Simulation Harness Launch]
  │     └── conhost.exe (PID 1948)
  └── SnippingTool.exe (PID 2616) [Analyst Diagnostic Capture]
```

---

## Step 4 — Command Line Reconstruction (`windows.cmdline`)

**Command Executed:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.cmdline > cmdline_output.txt
```

**Raw Output:** [`cmdline_output.txt`](./cmdline_output.txt)

**Key Findings:**
1. **Analyst Inspection Session (PID 6312):**
   - Command line:
     ```text
     "C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe" /SESSION:...
     ```
   - Decoded session payload (UTF-16LE inside base64 session descriptor):
     `C:\Users\Public\custom_behavior_sim.py`
   - Attribution: Analyst administrative review of the simulation script source prior to execution.
2. **Interactive PowerShell Sessions (PID 2428 & 4704):**
   - Both shells ran under user context `SimUser`.

---

## Step 5 — Network Sockets & Sockets Scanning (`windows.netscan`)

**Command Executed:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.netscan > netscan_output.txt
```

**Raw Output:** [`netscan_output.txt`](./netscan_output.txt)

**Findings:**
- **Active Sockets in Acquired Memory:** `0`
- **Listening Ports:** `0`
- **Foreign / Remote Endpoints:** `0`

**Defensible Forensic Evaluation:**
- Within the scope of the examined memory dump, `windows.netscan` identified zero active, listening, or residual TCP/UDP socket structures.
- This finding is consistent with the verified disconnected network configuration in VirtualBox and guest ping failures.
- No evidence of outbound command-and-control communication or data exfiltration was identified within the examined memory structures; this evaluation is qualified by the specific sources inspected and does not independently exclude transient prior activity.

---

## Step 6 — Injected Code & Memory Protections (`windows.malfind`)

**Command Executed:**
```powershell
vol.exe -f forensics\acquisition\DFIR-SimVM-memory.raw windows.malfind > malfind_output.txt
```

**Raw Output:** [`malfind_output.txt`](./malfind_output.txt)

**Evaluation of Findings:**
- Hits detected in:
  - `MsMpEng.exe` (PID 3124) — Microsoft Defender dynamic JIT signature evaluation buffers.
  - `TextInputHost.exe` (PID 5652) — Windows XAML input subsystem JIT compiler.
  - `powershell.exe` (PID 2428) — .NET CLR runtime JIT engine.
- **Negative Finding (Forensically Significant):** Zero instances of unbacked PE headers (`MZ` / `PE\0\0`), shellcode stagers, or hollowed processes were detected.
- **Conclusion:** The simulation operated strictly as a userland script execution without kernel rootkit hooks or in-memory process hollowing.

---

## Phase 3 Summary & Evidence Hand-off to Phase 4

| Forensic Question | Volatility 3 Answer | Corroborating Evidence |
|---|---|---|
| **What script was executed?** | `custom_behavior_sim.py` | Notepad session descriptor + PowerShell process trees |
| **Where was it staged?** | `C:\Users\Public\` | Command-line session data |
| **Were network sockets observed?** | **NO** | `netscan` reported 0 open/listening sockets in RAM; consistent with hypervisor adapter disconnection |
| **Was code injected into system processes?** | **NO** | `malfind` found only legitimate JIT runtime memory |
| **What active user artifacts remain?** | Interactive PowerShell shells + Notepad session | PIDs 2428, 4704, 6312 |

---

## Next Step

Proceed to **Phase 4: Disk Analysis with Autopsy** using the derived disk image:
- Primary Cloned Image: `forensics/acquisition/DFIR-SimVM-disk.vdi` (`EVD-002`)
- Derived Container for Autopsy: `forensics/acquisition/DFIR-SimVM-disk.vmdk` (`EVD-003`)
- Autopsy analysis guide: **[forensics/autopsy_analysis/ANALYSIS_NOTES.md](../autopsy_analysis/ANALYSIS_NOTES.md)**
