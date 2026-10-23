# Autopsy — Disk Forensics Analysis Notes
# Phase 4 — Independent Disk Examination

> **Investigator:** Yogesh T (Lead DFIR Analyst)  
> **Evidence Item:** `EVD-003` (`forensics/acquisition/DFIR-SimVM-disk.vmdk`, derived from `EVD-002`)  
> **Container SHA-256:** `98E32CEA9633D9F65AAC2A93F9236F3C31A12DD50797BF4DEB5E357D0166C219`  
> **Source VDI SHA-256:** `33695DE62EE72C8E3FDE8225BD7688D9CDFD656B22F1DB7EC51D08B63579B980` (`EVD-002`)  
> **Analysis Date:** 2026-10-23  
> **Tool:** Autopsy 4.23.1 (with The Sleuth Kit 4.12.1 backend)  
>
> **INVESTIGATION METHODOLOGY:** Attack timeline, file creation/modification events, and impact indicators were evaluated from disk structures and NTFS $MFT records following a structured forensic approach, and cross-referenced with memory findings and simulation execution logs.

---

## Case Information

- **Case Name:** `DFIR-Lab-001`
- **Case Number:** `2026-001`
- **Examiner:** `Yogesh T`
- **Data Source:** `DFIR-SimVM-disk.vmdk` (Derived Container Size: 38,354,026,496 bytes)
- **Primary Partition Analyzed:** `vol6 (Basic data partition)` — NTFS File System (Windows C: drive)

---

## Step 1 — File System & Directory MFT Analysis

**MFT Cryptographic Inventory:** [`directory_mft_listing.csv`](./directory_mft_listing.csv)  
**Timeline Export:** [`timeline_export.csv`](./timeline_export.csv)  
**Target Path Identified:** `/vol_vol6/Users/Public/test_ransomware_sim/B67F15E3/`

### Cryptographic MFT Inventory & Hash Verification:

| Filename | Modified Time (IST) | File Size | SHA-256 Digest | Status |
|---|---|---|---|---|
| `financial_report_Q3.xlsx.locked` | 2026-10-22 22:26:49 | 56 B | `87f684c93236712b8dddb6ff74806e509137c937685967ed46ca083c7c214b58` | Allocated |
| `employee_database.csv.locked` | 2026-10-22 22:26:50 | 70 B | `559de183772835077bc57ab56084eb1fe352193382a44bad30f42fe3c83425cf` | Allocated |
| `executive_memo.docx.locked` | 2026-10-22 22:26:50 | 53 B | `306dc22b77f5b16213c3b19a8f632cd9e77e71cc2832bfa777c4760a3b4828e8` | Allocated |
| `backup_keys.txt.locked` | 2026-10-22 22:26:51 | 48 B | `36fc10324925b747c069ac505e23aa075d369016a57c493c63adb8a83eb82111` | Allocated |
| `customer_list.txt.locked` | 2026-10-22 22:26:51 | 51 B | `59729db3db076a5d8098a9af334774f0a55f36bf2a4c123a38a2262d5e4f6213` | Allocated |
| `project_proposal.pdf.locked` | 2026-10-22 22:26:52 | 55 B | `14c4bc99cb86e6a796de389f90bfc9176ae5d72f8935e8bb9ab2d7744fbc1d70` | Allocated |
| `contract_draft.docx.locked` | 2026-10-22 22:26:53 | 55 B | `0880bc5140b68222094dbe064ed498594a741e540a843f89cb614bef637a6f16` | Allocated |
| `logo.png.locked` | 2026-10-22 22:26:53 | 34 B | `9714d1227d6ae085487e6f24a7551fbbfc999d13929ad69ea1f637c774a8a3ab` | Allocated |
| `recovery_journal.json` | 2026-10-22 22:26:54 | 17,465 B | `efc9af147d13daa6609d144da718502f64d7e3d550b6c2ef39e95b74a6664f23` | Allocated |
| `README_YOUR_FILES.txt` | 2026-10-22 22:26:55 | 1,144 B | `4a435bd0a701e61a1cfcab0275c301a548a556ac84599920ff005634ca792dce` | Allocated |
| `artifact_manifest.json` | 2026-10-22 22:26:55 | 13,854 B | `6d3a0c933b418fafe0bb0f523c98d88f6f20a800afc5538792596503488f4c79` | Allocated |
| `simulation_log.txt` | 2026-10-22 22:26:55 | 8,462 B | `e132277562d6420367d964891ccee11b36fbe50f85cb66c85b1c83a82f64603a` | Allocated |

---

## Step 2 — Timeline Reconstruction (Autopsy Timeline Tool)

**Screenshots:**
- Macro Activity Counts: [`screenshots/autopsy-timeline-counts.png`](../../screenshots/autopsy-timeline-counts.png)
- Detailed Sequence View: [`screenshots/autopsy-timeline.png`](../../screenshots/autopsy-timeline.png)

### Chronological Attack Flow Identified:

```text
22-Oct-2026 (Hour 22 IST / 16:00 UTC)
  ├── 1. Staging & Dropper Artifact:
  │      Path: C:\Users\Public\custom_behavior_sim.py
  │
  ├── 2. Rapid Encryption Burst (T1486):
  │      22:26:49 -> financial_report_Q3.xlsx encrypted
  │      22:26:50 -> employee_database.csv & executive_memo.docx encrypted
  │      22:26:51 -> backup_keys.txt & customer_list.txt encrypted
  │      22:26:52 -> project_proposal.pdf encrypted
  │      22:26:53 -> contract_draft.docx & logo.png encrypted
  │      (Duration: 4 seconds total across 8 files — automated script velocity)
  │
  ├── 3. Recovery Journal & Ransom Note Drop:
  │      22:26:54 -> recovery_journal.json committed
  │      22:26:55 -> README_YOUR_FILES.txt dropped & artifact_manifest.json written
  │
  └── 4. Recovery Inhibition Artifacts (T1490 Evaluation):
         /EFI/Microsoft/Boot/BCD access & query events recorded in timeline.
         (Evaluation & query only; live deletion was disabled via safe default mode)
```

---

## Step 3 — Extension Mismatches & Entropy Verification

- Autopsy's **Extension Mismatch Detector** flagged all 8 `.locked` files.
- The files retain generic MIME declarations (`application/octet-stream`), but their original signatures (`PK\x03\x04` for docx/xlsx, `%PDF` for pdf, `\x89PNG` for png) were replaced by the XOR transformation.
- This represents file signature modification and header alteration characteristic of ransomware file transformations.

---

## Step 4 — Deleted File Recovery Analysis

**Report:** [`deleted_files_report.md`](./deleted_files_report.md)
- **What NTFS $MFT Independently Shows:** The Master File Table independently records eight allocated files bearing `.locked` extensions and timestamps clustered tightly between 22:26:49 and 22:26:53 IST. It also reflects unlinked MFT records and volume allocation bitmap deallocations in the directory for the original pre-encryption filenames.
- **Attribution of the Atomic Staging Sequence:** The specific three-stage replacement sequence (`.stage.tmp` -> rename to `.locked` -> original file unlinking) is established through the simulator implementation and on-disk `recovery_journal.json` execution records, corroborated by the MFT timestamp ordering and cluster reallocation patterns.

---

## Corroboration: Memory (Phase 3) vs. Disk (Phase 4)

| Forensic Dimension | Phase 3: Volatility 3 Memory Finding | Phase 4: Autopsy Disk Finding | Forensic Conclusion |
|---|---|---|---|
| **Malware Script** | `custom_behavior_sim.py` in Notepad session descriptor | `C:\Users\Public\custom_behavior_sim.py` MFT entry | **Confirmed** staged script |
| **Execution Window** | Memory captured at 22:40:12 IST (17:10:12 UTC) | File modification burst at 22:26:49 – 22:26:55 IST | **Confirmed** timing |
| **Network & Exfiltration**| 0 active/listening sockets in `windows.netscan` | 0 outbound network artifacts in Autopsy Web/Recent Activity modules | **Consistent with isolation**; zero outbound network activity observed across examined memory and disk artifacts |
| **Recovery Inhibition** | Simulated log command in script stdout | `/EFI/Microsoft/Boot/BCD` access event in timeline | **Corroborated** T1490 evaluated in safe log mode |
| **Ransomware Note / Inspection** | Inspected via Notepad (analyst administrative review) | Dropped by simulation at `22:26:55 IST`, size 1,144 B | **Corroborated** extortion artifact dropped by script and inspected by analyst |

---

## Next Step

Proceed to **Phase 5: Incident Response & Forensic Report**:
- Deliverable: **[`docs/INCIDENT_RESPONSE_REPORT.md`](../../docs/INCIDENT_RESPONSE_REPORT.md)**
- Formal executive presentation documenting timeline, IOCs, root cause, and remediation guidance.
