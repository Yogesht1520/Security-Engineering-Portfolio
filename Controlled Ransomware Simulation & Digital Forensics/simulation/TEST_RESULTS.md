# Simulation Test Suite Execution Record
# Automated Crash Recovery & Fault-Tolerance Verification

> **Test Suite:** `simulation/test_crash_recovery.py`  
> **Target System:** `simulation/custom_behavior_sim.py` (v1.2.12)  
> **Status:** ✅ **15 / 15 PASSED (100%)**  
> **Verification Date:** 2026-10-23  

---

## 1. Test Environment Specification

| Parameter | Host Workstation Specification |
|---|---|
| **Operating System** | Microsoft Windows 11 Enterprise (64-bit, Build 26100) |
| **Python Runtime** | CPython 3.13.1 (`python.exe` / `py -3`) |
| **Test Runner** | Python Standard Library `unittest` |
| **Execution Command** | `py -3 simulation/test_crash_recovery.py` (or `python simulation/test_crash_recovery.py`) |
| **Execution Time** | ~1.355 seconds |

---

## 2. Test Suite Overview & Coverage Matrix

The automated test suite verifies that `custom_behavior_sim.py` guarantees strict containment, atomic rollback safety, and forensic artifact preservation under harsh simulated failure modes:

| Test ID | Scenario Name | Test Method | Primary Verification Objective | Result |
|---|---|---|---|:---:|
| **SC-01** | Basic Restore | `test_01_basic_restore` | Verifies clean end-to-end file encryption and reverse restoration | ✅ PASS |
| **SC-02** | Crash Mid-Encryption (Staging File) | `test_02_crash_mid_encryption_staging_file` | Validates recovery when crash occurs while `.stage.tmp` is pending | ✅ PASS |
| **SC-03** | Crash Post-Rename | `test_03_crash_post_rename_pre_unlink` | Validates recovery when crash occurs immediately post-atomic rename | ✅ PASS |
| **SC-04** | Missing Primary Manifest Fallback | `test_04_missing_primary_manifest_fallback_to_journal` | Fallback to atomic `recovery_journal.json` if manifest is lost | ✅ PASS |
| **SC-05** | Corrupt Primary Manifest Fallback | `test_05_corrupt_primary_manifest_fallback_to_journal` | Journal fallback when `artifact_manifest.json` contains malformed JSON | ✅ PASS |
| **SC-06** | Journal Mid-Write Incomplete Line | `test_06_journal_mid_write_incomplete_line` | Recovery engine skips uncommitted journal records safely | ✅ PASS |
| **SC-07** | Partial Failure During Decryption | `test_07_partial_failure_during_decryption` | Partial decryption failure preserves untransformed files | ✅ PASS |
| **SC-08** | Directory Traversal Containment | `test_08_directory_traversal_path_injection` | Rejects malicious traversal paths escaping the designated run directory | ✅ PASS |
| **SC-09** | Tampered Primary Ciphertext | `test_09_tampered_primary_file_fallback_to_staging` | Detects hash mismatch on `.locked` file and falls back to intact staging file | ✅ PASS |
| **SC-10** | Orphaned Encrypted File Tampered | `test_10_orphaned_encrypted_file_tampered_skipped` | Preserves tampered orphaned file on disk without corrupting system state | ✅ PASS |
| **SC-11** | Permission Denied on Target File | `test_11_permission_denied_on_target_file` | Handles unreadable files gracefully without crashing the pipeline | ✅ PASS |
| **SC-12** | Atomic Rename Collision | `test_12_atomic_rename_collision` | Protects against race conditions if target filename already exists | ✅ PASS |
| **SC-13** | Corrupt Journal Safe Fallback | `test_13_corrupt_journal_safe_fallback` | Refuses unsafe restore when both manifest and journal are compromised | ✅ PASS |
| **SC-14** | Selective Artifact Cleanup Halting | `test_14_selective_cleanup_on_failure` | Preserves logs, journals, and notes if any cleanup error occurs | ✅ PASS |
| **SC-15** | Preserves Forensic Evidence on Tamper | `test_15_preserves_forensic_evidence_on_tamper` | Halts artifact deletion when evidentiary tampering is detected | ✅ PASS |

---

## 3. Representative Execution Console Output

```text
PS C:\Users\yoges\Documents\Security-Engineering-Portfolio\Controlled Ransomware Simulation & Digital Forensics> py -3 simulation/test_crash_recovery.py
    SAFETY: Hash mismatch on orphaned encrypted file doc10.txt.locked! Preserving file.
      Expected (encrypted): bd6352945ed229a102a0cb34b625fc08ae60bc03bfa2f394fa6da602e7fb2163
      Actual on disk:       41b2590b0f6dc08e16a085d38d32ff13c6e1ec7952964cf9bffdf12a41b8461e
[RESTORE] Skipping cleanup of ransom note, journal, and log — errors occurred.
  Artifacts preserved for investigation. Fix errors and re-run --restore.
.[RESTORE] MANIFEST ABORT: Path escapes run directory.
  Field   : original_path
  Path    : C:\Users\yoges\AppData\Local\Temp\system_critical_file.txt
  Run dir : C:\Users\yoges\AppData\Local\Temp\dfir_recovery_test_9oir5ppx\RUN001
Entire manifest rejected. No files were modified.
.    Failed to move restored file into destination doc12.txt: Destination C:\Users\yoges\AppData\Local\Temp\dfir_recovery_test_xo5050pz\RUN001\doc12.txt already exists.
[RESTORE] Skipping cleanup of ransom note, journal, and log — errors occurred.
  Artifacts preserved for investigation. Fix errors and re-run --restore.
.  [RESTORE] Halting artifact cleanup: simulation_log.txt could not be removed. Preserving remaining evidence.
.......[RESTORE] Manifest at artifact_manifest.json is incomplete (status='IN_PROGRESS_PRE_ENCRYPTION', records=0).
.[RESTORE] File doc6.txt has latest journal status 'FAILED' (error: Simulated I/O failure during committed journal write).
..[RESTORE] Manifest at artifact_manifest.json is incomplete (status='IN_PROGRESS_PRE_ENCRYPTION', records=0).
[RESTORE] Failed to read recovery journal fallback: Expecting property name enclosed in double quotes: line 1 column 2 (char 1). Aborting to prevent unsafe restore.
.    Candidate encrypted file doc9.txt.locked failed SHA-256 verification (got 4c169feec6cc91f7..., expected 780d626181406f02...).
    [RECOVERY] Primary encrypted file doc9.txt.locked was invalid/tampered; falling back to verified staging file doc9.txt.stage.tmp.
[RESTORE] Forensic anomalies / tampered artifacts preserved despite successful file restoration:
  Evidence: Tampered primary file doc9.txt.locked preserved on disk (restored via staging fallback)
  PRESERVING recovery journal, ransom note, and simulation log for forensic investigation.
.
----------------------------------------------------------------------
Ran 15 tests in 1.355s

OK
```

---

## 4. How to Reproduce Locally

Any evaluator or security engineer can independently execute this test suite on Windows, macOS, or Linux:

```powershell
# Windows
py -3 simulation/test_crash_recovery.py

# Linux / macOS
python3 simulation/test_crash_recovery.py
```
No third-party packages are required; only standard Python libraries (`unittest`, `hashlib`, `tempfile`, `pathlib`, `os`, `shutil`) are utilized.
