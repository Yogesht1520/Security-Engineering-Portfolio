# SAFETY.md — Non-Negotiable Safety Rules

> This file is the foundational safety policy for this repository.  
> Read it before touching anything else.

---

## The One Rule That Supersedes Everything

**The simulation VM must NEVER be connected to any network — not your home network, not the internet, not a corporate VPN, not a host-only adapter with routing enabled. The network adapter must be set to "Not Attached" in the hypervisor settings.**

A screenshot documenting this is preserved in `screenshots/vm-network-adapter-disabled.png` and verified before simulation execution.

---

## Absolute Prohibitions

| # | Rule | Rationale |
|---|---|---|
| 1 | **NEVER** download or execute real, live ransomware or malware samples | Even from "research" repositories. The behavioral-simulation approach achieves targeted forensic-learning outcomes with zero risk. This is not a limitation — it is a deliberate, professional judgment call. |
| 2 | **NEVER** attach the simulation VM to any network during or after simulation | Including host-only adapters unless explicitly bridged to nothing. Use "Not Attached." |
| 3 | **NEVER** run simulation artifacts on your host machine | Host OS, shared drives, or any machine containing real personal or work data are strictly out of scope. |
| 4 | **NEVER** use production credentials, real personal files, or anything of value inside the VM | The VM is a throwaway research environment. |
| 5 | **NEVER** skip taking a clean snapshot before running any simulation | VirtualBox baseline snapshot must exist before execution. Post-simulation, revert — do not attempt manual cleanup. |

---

## What IS In Scope (Safe Simulation Approaches)

### Approach A — Custom Behavior Simulation Script (Executed in this Lab)

- A self-written Python script (`simulation/custom_behavior_sim.py`, v1.2.12)
- Confined strictly to `C:\Users\Public\test_ransomware_sim\<RUN_ID>\` inside the VM
- Performs: canary file staging, mass file renaming (`.locked`), reversible XOR transformation (byte key `0xAB`), dropping an extortion note text file, and writing a cryptographic recovery journal (`recovery_journal.json`)
- Evaluates T1490 command parameters in safe log-only mode by default without live subprocess execution
- Does NOT: exfiltrate data, establish network sockets, escalate privileges, modify system files, or touch anything outside the target test path

### Approach B — Atomic Red Team (Test Plan Reference)

- Open-source, MIT-licensed, MITRE ATT&CK-mapped test procedures (see `simulation/atomic_red_team_tests.md`)
- Non-destructive: simulates command invocations associated with ransomware techniques
- Produces relevant, controlled forensic observables: process trees, command-line history, registry queries, and shadow-copy deletion command events

### Excluded from Scope: Credential Dumping (Mimikatz)

- Credential dumping utilities (e.g., Mimikatz, LSASS memory dumping) were **explicitly excluded from the scope of this exercise** to keep the forensic focus centered squarely on ransomware staging, file transformation bursts (T1486), recovery-inhibition evaluation (T1490), and volatile memory socket audits.

---

## Verification Checklist (Execution Sequence for this Run)

- [x] VirtualBox installed on host machine
- [x] Target VM (`DFIR-SimVM`) installed with Windows 11 Enterprise x64
- [x] Simulation script staged in guest path: `C:\Users\Public\custom_behavior_sim.py`
- [x] Virtual network adapter confirmed and set to **"Not Attached"** in VM Settings > Network
- [x] Hypervisor settings screenshot verified: `screenshots/vm-network-adapter-disabled.png`
- [x] Guest ping loop connectivity test verified (100% packet loss): `screenshots/network-connectivity-test.png`
- [x] Clean baseline snapshot taken: `baseline-pre-simulation-2026-10-22`
- [x] Confirmed: no personal files, no production credentials inside the VM

---

## After the Exercise

- Revert the VM to the clean baseline snapshot (`baseline-pre-simulation-2026-10-22`)
- Confirm no simulation artifacts remain on the host machine
- Forensic disk images and memory dumps are stored in local encrypted analyst storage (`E:\ForensicEvidence\DFIR-Lab-001\`) and excluded from Git

---

## Legal & Ethical Notice

This project is conducted exclusively for educational purposes, inside a self-owned, isolated virtual environment, using only non-destructive simulation tools. No real systems, networks, or data are involved. This work aligns with responsible security research practices and does not violate any laws or terms of service.

---

*If you are a recruiter or hiring manager reviewing this portfolio: the existence of this SAFETY.md, and the fact that the author chose behavioral simulation over live malware samples, is an intentional signal of security maturity and professional judgment.*
