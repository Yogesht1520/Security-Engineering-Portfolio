# SAFETY.md — Non-Negotiable Safety Rules

> This file is the most important file in this repository.
> Read it before touching anything else.

---

## The One Rule That Supersedes Everything

**The simulation VM must NEVER be connected to any network — not your home network, not the internet,
not a corporate VPN, not a host-only adapter with routing enabled. The network adapter must be set to
"Not Attached" in the hypervisor settings.**

A screenshot proving this is in `screenshots/vm-network-adapter-disabled.png` and must exist before Phase 1 begins.

---

## Absolute Prohibitions

| # | Rule | Rationale |
|---|---|---|
| 1 | **NEVER** download or execute real, live ransomware or malware samples | Even from "research" repositories. The behavioral-simulation approach achieves identical forensic-learning outcomes with zero risk. This is not a limitation — it is a deliberate, professional judgment call. |
| 2 | **NEVER** attach the simulation VM to any network during or after simulation | Including host-only adapters unless explicitly bridged to nothing. Use "Not Attached." |
| 3 | **NEVER** run simulation artifacts on your host machine | Host OS, shared drives, or any machine containing real personal or work data are out of scope. |
| 4 | **NEVER** use production credentials, real personal files, or anything of value inside the VM | The VM is a throwaway environment. |
| 5 | **NEVER** skip taking a clean snapshot before running any simulation | VirtualBox snapshot before anything is executed. If something goes wrong, revert — do not attempt to clean up manually. |

---

## What IS In Scope (Safe Simulation Approaches)

### Option A — Atomic Red Team (Recommended)

- Open-source, MIT-licensed, MITRE ATT&CK-mapped test scripts
- Non-destructive: they simulate the *command invocations* associated with ransomware techniques, not the destructive payload itself
- Produces identical forensic artifacts: process trees, command-line history, registry changes, shadow-copy deletion attempts
- Each test is individually auditable — you can read exactly what it will do before running it

### Option B — Custom Behavior Simulation Script

- A self-written Python script (see `simulation/custom_behavior_sim.py`)
- Confined entirely to a `test_target/` directory inside the VM
- Performs: mass file renaming with a `.locked` extension, trivial XOR "encryption" (not real encryption), dropping a fake ransom note text file
- Every action is documented in the script's comments — no surprises
- Does NOT: exfiltrate data, escalate privileges, modify system files, or touch anything outside the test directory

### Option C — Mimikatz (Advanced, Optional)

- Only if you are comfortable safely handling a tool flagged by every AV
- Run strictly offline inside the VM
- Purpose: to create an LSASS memory dump artifact for Volatility analysis
- You must understand exactly what it does before running it

---

## Verification Checklist (Complete Before Phase 1)

- [ ] VirtualBox installed on host
- [ ] VM created with OS installed
- [ ] Network adapter confirmed as "Not Attached" in VM Settings > Network
- [ ] Screenshot taken: `screenshots/vm-network-adapter-disabled.png`
- [ ] Clean baseline snapshot taken BEFORE any simulation code is copied into the VM
- [ ] Snapshot name documented (e.g., `baseline-clean-YYYY-MM-DD`)
- [ ] Confirmed: no personal files, no real credentials inside the VM

---

## After the Exercise

- Revert the VM to the clean baseline snapshot OR fully delete the VM
- Confirm no simulation artifacts remain on the host machine
- If using a disk image exported to host: store in an encrypted, clearly labeled folder, and delete after the portfolio is complete

---

## Legal & Ethical Notice

This project is conducted exclusively for educational purposes, inside a self-owned, isolated virtual
environment, using only non-destructive simulation tools. No real systems, networks, or data are
involved. This work aligns with responsible security research practices and does not violate any laws
or terms of service.

---

*If you are a recruiter or hiring manager reviewing this portfolio: the existence of this SAFETY.md,
and the fact that the author chose behavioral simulation over live malware samples, is an intentional
signal of security maturity and professional judgment.*
