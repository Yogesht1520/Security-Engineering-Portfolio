#!/usr/bin/env python3
"""
custom_behavior_sim.py — Version 1.2.12
======================================
Controlled Ransomware Behavior Simulation Script
Project: DFIR Lab — Controlled Ransomware Simulation & Digital Forensics Investigation

For full version history and detailed change notes, see CHANGELOG.md.

SAFETY DECLARATION
------------------
This script is:
  - Entirely self-written and fully understood line-by-line
  - Confined EXCLUSIVELY to a unique subdirectory of TEST_TARGET_DIR
  - Non-destructive beyond the test subdirectory
  - XOR is trivially reversible: XOR(XOR(data, key), key) == data
  - T1490 system commands do NOT execute unless --live-t1490 is passed explicitly
  - Designed to produce realistic forensic ARTIFACTS, not to cause real harm

USAGE
-----
  # Default (safe) — file operations only, T1490 logged but NOT executed:
  py custom_behavior_sim.py

  # Skip T1490 subprocess logging too — just file artifacts:
  py custom_behavior_sim.py --skip-t1490

  # True dry run — no filesystem changes, print only:
  py custom_behavior_sim.py --dry-run

  # Live T1490 — actually executes vssadmin + bcdedit (requires extra confirmation):
  py custom_behavior_sim.py --live-t1490

  # Restore files from a previous run using its manifest or recovery journal:
  py custom_behavior_sim.py --restore --manifest <path_to_artifact_manifest.json>
  py custom_behavior_sim.py --restore --journal <path_to_recovery_journal.json>

  # Skip interactive confirmation (safe mode only):
  py custom_behavior_sim.py --yes

DO NOT run this script on your host machine.
DO NOT run this script on any machine containing real data.
This script is intended to run ONLY inside the air-gapped simulation VM.

Author: Yogesh T (Lead DFIR Analyst)
Version: 1.2.12
Date: 2026-10-22
MITRE ATT&CK Techniques Simulated:
  T1486 — Data Encrypted for Impact  (file XOR + rename to .locked)
  T1490 — Inhibit System Recovery    (command logged; executed only with --live-t1490)
  T1083 — File and Directory Discovery (directory enumeration, confined to run dir)
"""

import os
import sys
import json
import uuid
import time
import hashlib
import logging
import platform
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path


# ===========================================================================
# CONFIGURATION
# ===========================================================================

# Base target directory — the script creates a unique child directory here
BASE_TARGET_DIR = r"C:\Users\Public\test_ransomware_sim"

# Approved parent directories — run directory must be a true child of one of these
SAFE_PARENT_DIRS = [
    Path(r"C:\Users\Public"),
    Path(r"C:\Temp"),
    Path(r"C:\tmp"),
    Path(r"C:\forensic_test"),
]

XOR_KEY = 0xAB
TARGET_EXTENSIONS = frozenset([".txt", ".docx", ".pdf", ".xlsx", ".jpg", ".png", ".csv"])
ENCRYPTED_EXTENSION = ".locked"
RANSOM_NOTE_FILENAME = "README_YOUR_FILES.txt"


# ===========================================================================
# ARGUMENT PARSING — mutually exclusive mode flags
# ===========================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Controlled ransomware behavior simulation v1.2.12 — DFIR Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Execution modes (mutually exclusive):
  (default)      Safe mode: file operations + T1490 command logging only
  --skip-t1490   File operations only; T1490 commands not even logged
  --dry-run      True read-only: no filesystem changes, print only
  --live-t1490   Execute vssadmin + bcdedit (requires extra confirmation)
  --restore      Reverse a previous run using manifest JSON or recovery journal
        """
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="True read-only mode. No filesystem changes. Prints what would happen."
    )
    mode.add_argument(
        "--skip-t1490",
        action="store_true",
        help="File operations only. T1490 commands are not logged or executed."
    )
    mode.add_argument(
        "--live-t1490",
        action="store_true",
        help="Actually execute vssadmin + bcdedit. Requires additional confirmation. "
             "Use only inside the air-gapped VM when you need real T1490 forensic artifacts."
    )
    mode.add_argument(
        "--restore",
        action="store_true",
        help="Restore a previous run using its artifact manifest."
    )

    parser.add_argument(
        "--manifest",
        type=str,
        default=None,
        help="Path to artifact_manifest.json (for --restore)."
    )
    parser.add_argument(
        "--journal",
        type=str,
        default=None,
        help="Path to recovery_journal.json (for crash recovery --restore when manifest is absent)."
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Skip the interactive confirmation prompt (not applicable to --live-t1490 extra confirmation)."
    )

    args = parser.parse_args()

    # --restore requires --manifest or --journal
    if args.restore and not args.manifest and not args.journal:
        parser.error("--restore requires either --manifest <path> or --journal <path>")

    return args


# ===========================================================================
# LOGGING — stdout + file handler
# ===========================================================================

def setup_logging(log_path: Path) -> None:
    """Configure logging to both stdout and a file."""
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    root.addHandler(ch)

    # File handler — creates the log file
    try:
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        root.addHandler(fh)
        logging.info(f"[LOGGING] File handler active: {log_path}")
    except OSError as e:
        logging.warning(f"[LOGGING] Could not open log file {log_path}: {e} — stdout only.")


log = logging.getLogger("ransomware_sim_v1.2.12")


# ===========================================================================
# UTILITY
# ===========================================================================

def sha256_file(filepath: Path) -> str:
    """SHA-256 hash of a file. Returns hex digest or 'ERROR:<msg>'."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        return f"ERROR:{e}"


def safe_unlink_file(filepath: Path, label: str = "file") -> bool:
    """
    Safely unlink a file with explicit exception handling.
    Returns True if unlinked or nonexistent; False if an OSError occurs.
    """
    if not filepath.exists():
        return True
    try:
        filepath.unlink()
        return True
    except OSError as e:
        log.warning(f"  [CLEANUP] Could not remove {label} {filepath.name}: {e}")
        return False


def file_timestamps(filepath: Path) -> dict:
    """
    Return file timestamps with platform-aware labels.

    Windows:  st_ctime == file creation time (birth time)
    Linux:    st_ctime == inode change time; birthtime via os.stat_result if supported
    Label 'birth_time_utc' is used for Windows st_ctime to avoid the misleading 'ctime' name.
    """
    try:
        stat = filepath.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        size = stat.st_size

        if platform.system() == "Windows":
            birth = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
            return {"birth_time_utc": birth, "mtime_utc": mtime, "size_bytes": size}
        else:
            # Linux: use st_birthtime if available (macOS/some Linux), else st_ctime
            birth_ts = getattr(stat, "st_birthtime", stat.st_ctime)
            birth = datetime.fromtimestamp(birth_ts, tz=timezone.utc).isoformat()
            change = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
            return {
                "birth_time_utc": birth,
                "metadata_change_time_utc": change,
                "mtime_utc": mtime,
                "size_bytes": size,
            }
    except OSError as e:
        return {"error": str(e)}


def simulation_process_context() -> dict:
    """
    Capture execution context of this simulation process.

    NOTE: This is NOT T1057 (Process Discovery). It records only the current
    Python process's own metadata — PID, PPID, interpreter path — for evidence
    chain documentation. It does not enumerate other running processes.
    """
    pid = os.getpid()
    ppid_val = "N/A"
    parent_name = "N/A"

    try:
        import psutil
        proc = psutil.Process(pid)
        ppid_val = proc.ppid()
        parent = psutil.Process(ppid_val)
        parent_name = parent.name()
    except Exception:
        # Broad except: psutil may not be installed, or may fail for various reasons
        try:
            ppid_val = os.getppid() if hasattr(os, "getppid") else "N/A"
        except Exception:
            pass

    return {
        "pid": pid,
        "ppid": ppid_val,
        "parent_process_name": parent_name,
        "interpreter": sys.executable,
        "argv": sys.argv,
        "note": "Simulation process context only — not T1057 process enumeration",
    }


# ===========================================================================
# SAFETY — Strict path boundary (P0, Issue 3)
# ===========================================================================

def enforce_safety_boundary(path: Path) -> Path:
    """
    Resolve the path fully (expands symlinks and '..' components) then verify
    it is a true subdirectory of an approved parent via is_relative_to().

    Prevents traversal like: C:\\Users\\Public\\..\\Windows
    which resolves to C:\\Windows and must be rejected.
    """
    try:
        resolved = path.resolve()
    except (OSError, ValueError) as e:
        log.critical(f"SAFETY ABORT: Cannot resolve path '{path}': {e}")
        sys.exit(1)

    is_safe = any(
        resolved.is_relative_to(parent.resolve())
        for parent in SAFE_PARENT_DIRS
    )

    if not is_safe:
        log.critical("=" * 65)
        log.critical("SAFETY ABORT: Path is not within any approved parent directory.")
        log.critical(f"  Resolved: {resolved}")
        log.critical(f"  Approved: {[str(p) for p in SAFE_PARENT_DIRS]}")
        log.critical("=" * 65)
        sys.exit(1)

    return resolved


# ===========================================================================
# RESTORE MODE — manifest-driven & journal-driven crash recovery
# ===========================================================================

def load_restore_records(target_path: Path) -> tuple:
    """
    Load restoration records and run directory from either:
    1. artifact_manifest.json (standard workflow)
    2. recovery_journal.json (crash recovery workflow)
    Detects incomplete/in-progress manifests and falls back to journal automatically.
    Returns: (run_dir, encrypted_records, sim_id)
    """
    if not target_path.exists():
        # Check if fallback journal exists in the same directory
        candidate_journal = target_path.parent / "recovery_journal.json"
        if candidate_journal.exists():
            log.warning(f"[RESTORE] Manifest not found at {target_path}.")
            log.info(f"[RESTORE] Found recovery journal: {candidate_journal}. Falling back to crash recovery.")
            target_path = candidate_journal
        else:
            log.critical(f"[RESTORE] File not found: {target_path}")
            sys.exit(1)

    log.info(f"[RESTORE] Loading restoration data from: {target_path}")
    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.critical(f"[RESTORE] Cannot parse {target_path}: {e}")
        sys.exit(1)

    # Finding 2 fix: Detect if manifest is incomplete or in-progress
    if isinstance(data, dict):
        status = data.get("status", "")
        encrypted_records = data.get("phase_4_encrypted_files", [])
        if status != "SUCCESS" or not encrypted_records or "IN_PROGRESS" in status:
            candidate_journal = target_path.parent / "recovery_journal.json"
            if candidate_journal.exists():
                log.warning(f"[RESTORE] Manifest at {target_path.name} is incomplete (status='{status}', records={len(encrypted_records)}).")
                log.info(f"[RESTORE] Found recovery journal: {candidate_journal}. Falling back to crash recovery.")
                try:
                    with open(candidate_journal, "r", encoding="utf-8") as jf:
                        journal_data = json.load(jf)
                    if isinstance(journal_data, list):
                        data = journal_data
                        target_path = candidate_journal
                    else:
                        log.critical("[RESTORE] Recovery journal format invalid. Aborting to prevent unsafe restore.")
                        sys.exit(1)
                except Exception as e:
                    log.critical(f"[RESTORE] Failed to read recovery journal fallback: {e}. Aborting to prevent unsafe restore.")
                    sys.exit(1)
            else:
                log.critical(f"[RESTORE] Manifest at {target_path.name} is incomplete and no recovery_journal.json found. Aborting.")
                sys.exit(1)

    if isinstance(data, dict):
        # Completed artifact_manifest.json
        sim_id = data.get("simulation_id", "UNKNOWN")
        run_dir_str = data.get("run_directory", "")
        run_dir = Path(run_dir_str) if run_dir_str else target_path.parent
        encrypted_records = data.get("phase_4_encrypted_files", [])
        return run_dir, encrypted_records, sim_id

    elif isinstance(data, list):
        # Crash recovery from recovery_journal.json
        log.info("[RESTORE] Parsing recovery journal (crash recovery mode).")
        run_dir = target_path.parent
        sim_id = f"RECOVERY-{run_dir.name}"

        # Finding 3 fix: Track latest entry per original_path while carrying forward known valid hashes & paths
        consolidated = {}
        for entry in data:
            if not isinstance(entry, dict):
                continue
            orig = entry.get("original_path")
            if not orig:
                continue

            if orig not in consolidated:
                consolidated[orig] = {
                    "original_path": orig,
                    "encrypted_path": None,
                    "staged_path": None,
                    "pre_modification_sha256": None,
                    "post_modification_sha256": None,
                    "latest_status": None,
                    "latest_entry": None,
                }

            if entry.get("encrypted_path") or entry.get("target_path"):
                consolidated[orig]["encrypted_path"] = entry.get("encrypted_path") or entry.get("target_path")
            if entry.get("staged_path"):
                consolidated[orig]["staged_path"] = entry.get("staged_path")
            if entry.get("pre_modification_sha256"):
                consolidated[orig]["pre_modification_sha256"] = entry.get("pre_modification_sha256")
            if entry.get("post_modification_sha256") or entry.get("expected_sha256"):
                consolidated[orig]["post_modification_sha256"] = entry.get("post_modification_sha256") or entry.get("expected_sha256")

            consolidated[orig]["latest_status"] = entry.get("status")
            consolidated[orig]["latest_entry"] = entry

        encrypted_records = []
        for orig, info in consolidated.items():
            status = info["latest_status"]
            enc_path = info["encrypted_path"]
            staged_path = info["staged_path"]
            pre_hash = info["pre_modification_sha256"]
            post_hash = info["post_modification_sha256"]
            orig_file = Path(orig)

            if status == "FAILED":
                log.warning(f"[RESTORE] File {orig_file.name} has latest journal status 'FAILED' (error: {info['latest_entry'].get('error')}).")
                if orig_file.exists() and pre_hash and sha256_file(orig_file) == pre_hash:
                    log.info(f"  [RESTORE] Original {orig_file.name} is intact on disk with matching pre-hash.")
                    encrypted_records.append({
                        "original_path": orig,
                        "encrypted_path": enc_path,
                        "staged_path": staged_path,
                        "pre_modification_sha256": pre_hash,
                        "post_modification_sha256": post_hash,
                        "journal_status": status,
                    })
                elif enc_path and Path(enc_path).exists() and post_hash:
                    log.info(f"  [RESTORE] Encrypted destination exists for {orig_file.name}; attempting recovery using carried-forward hash.")
                    encrypted_records.append({
                        "original_path": orig,
                        "encrypted_path": enc_path,
                        "staged_path": staged_path,
                        "pre_modification_sha256": pre_hash,
                        "post_modification_sha256": post_hash,
                        "journal_status": status,
                    })
                else:
                    log.error(f"  [RESTORE] File {orig_file.name} failed without verifiable backup. Skipping.")
                    continue

            elif status in ("COMMITTED", "PRE_UNLINK_COMMITTED", "STAGED_VERIFIED"):
                encrypted_records.append({
                    "original_path": orig,
                    "encrypted_path": enc_path,
                    "staged_path": staged_path,
                    "pre_modification_sha256": pre_hash,
                    "post_modification_sha256": post_hash,
                    "journal_status": status,
                })
            else:
                if orig_file.exists():
                    encrypted_records.append({
                        "original_path": orig,
                        "encrypted_path": enc_path,
                        "staged_path": staged_path,
                        "pre_modification_sha256": pre_hash,
                        "post_modification_sha256": post_hash,
                        "journal_status": status,
                    })

        log.info(f"[RESTORE] Extracted {len(encrypted_records)} recoverable file records from journal.")
        return run_dir, encrypted_records, sim_id

    else:
        log.critical(f"[RESTORE] Unrecognized JSON format in {target_path}: expected object or list.")
        sys.exit(1)


def restore_mode(target_path_str: str) -> int:
    """
    Restore a previous simulation run using its artifact manifest or recovery journal.
    Supports seamless crash recovery if the run was interrupted before manifest generation.
    """
    target_path = Path(target_path_str)
    run_dir, encrypted_records, sim_id = load_restore_records(target_path)

    log.info(f"[RESTORE] Simulation ID: {sim_id}")
    log.info(f"[RESTORE] Run directory:  {run_dir}")

    # Enforce safety boundary on the run directory
    run_dir = enforce_safety_boundary(run_dir)

    if not encrypted_records:
        log.warning("[RESTORE] No encrypted file records found to restore.")
        return 0

    restored_count = 0
    error_count = 0
    hash_failures = []
    forensic_anomalies = []

    # Critical fix: validate every path in the manifest against the run_dir
    # BEFORE any file operation. A single out-of-bounds path rejects the whole manifest.
    log.info("[RESTORE] Validating all target paths against run directory...")
    for i, rec in enumerate(encrypted_records):
        for field in ("encrypted_path", "staged_path", "original_path"):
            raw_path = rec.get(field)
            if not raw_path:
                continue
            try:
                resolved = Path(raw_path).resolve()
            except (OSError, ValueError) as e:
                log.critical(f"[RESTORE] MANIFEST ABORT: Cannot resolve '{raw_path}': {e}")
                sys.exit(1)
            if not resolved.is_relative_to(run_dir):
                log.critical("[RESTORE] MANIFEST ABORT: Path escapes run directory.")
                log.critical(f"  Field   : {field}")
                log.critical(f"  Path    : {resolved}")
                log.critical(f"  Run dir : {run_dir}")
                log.critical("Entire manifest rejected. No files were modified.")
                sys.exit(1)
    log.info("[RESTORE] All manifest paths validated. Proceeding with restoration.")

    for rec in encrypted_records:
        orig_path = Path(rec["original_path"]).resolve()
        enc_path = Path(rec["encrypted_path"]).resolve() if rec.get("encrypted_path") else None
        staged_path = Path(rec["staged_path"]).resolve() if rec.get("staged_path") else None

        expected_enc_hash = rec.get("post_modification_sha256", "")
        expected_orig_hash = rec.get("pre_modification_sha256", "")

        log.info(f"  [RESTORE] Processing: {orig_path.name} (state: {rec.get('journal_status', 'MANIFEST')})")

        # 1. First check: Does original file exist intact on disk?
        if orig_path.exists():
            actual_orig_hash = sha256_file(orig_path)
            if actual_orig_hash == expected_orig_hash:
                log.info(f"    [RECOVERY] Original {orig_path.name} is already intact (SHA-256 matches pre-sim).")
                orphan_cleanup_failed = False
                for orphan_label, orphan_file in [("encrypted file", enc_path), ("staging file", staged_path)]:
                    if orphan_file and orphan_file.exists():
                        if not expected_enc_hash:
                            log.error(f"    SAFETY: Expected encrypted hash missing! Preserving orphaned {orphan_label}: {orphan_file.name}")
                            forensic_anomalies.append(f"Orphaned {orphan_label} {orphan_file.name} (missing expected hash)")
                            orphan_cleanup_failed = True
                            continue
                        orphan_hash = sha256_file(orphan_file)
                        if orphan_hash == expected_enc_hash:
                            log.info(f"    [RECOVERY] Removing verified orphaned {orphan_label}: {orphan_file.name}")
                            if not safe_unlink_file(orphan_file, f"verified orphaned {orphan_label}"):
                                orphan_cleanup_failed = True
                        else:
                            log.error(f"    SAFETY: Hash mismatch on orphaned {orphan_label} {orphan_file.name}! Preserving file.")
                            log.error(f"      Expected (encrypted): {expected_enc_hash}")
                            log.error(f"      Actual on disk:       {orphan_hash}")
                            forensic_anomalies.append(f"Orphaned {orphan_label} {orphan_file.name} (hash mismatch; preserved)")
                            orphan_cleanup_failed = True
                if orphan_cleanup_failed:
                    error_count += 1
                else:
                    restored_count += 1
                continue
            else:
                log.error(f"    SAFETY: Original exists but hash mismatch! Refusing to overwrite: {orig_path.name}")
                log.error(f"      Expected (pre-sim): {expected_orig_hash}")
                log.error(f"      Actual on disk:     {actual_orig_hash}")
                error_count += 1
                continue

        # 2. Original does NOT exist: find candidate encrypted source file
        # Check both primary encrypted file (.locked) and staging file (.stage.tmp).
        # Prioritize primary, but if primary is corrupted/tampered, fall back to intact staging file.
        source_file = None
        candidates = []
        if enc_path and enc_path.exists():
            candidates.append(enc_path)
        if staged_path and staged_path.exists() and staged_path != enc_path:
            candidates.append(staged_path)

        for cand in candidates:
            cand_hash = sha256_file(cand)
            if cand_hash == expected_enc_hash:
                source_file = cand
                if cand == staged_path and enc_path and enc_path.exists():
                    log.warning(f"    [RECOVERY] Primary encrypted file {enc_path.name} was invalid/tampered; falling back to verified staging file {cand.name}.")
                    forensic_anomalies.append(f"Tampered primary file {enc_path.name} preserved on disk (restored via staging fallback)")
                break
            else:
                log.warning(f"    Candidate encrypted file {cand.name} failed SHA-256 verification (got {cand_hash[:16]}..., expected {expected_enc_hash[:16]}...).")

        if not source_file:
            log.error(f"    No verified encrypted or staged file found for {orig_path.name}. Skipping.")
            hash_failures.append(str(orig_path))
            error_count += 1
            continue

        # 3. Source file hash is verified: Proceed to atomic staged decryption
        actual_source_hash = sha256_file(source_file)

        # 4. Atomic Staged Decryption:
        # Decrypt into a temporary restore file, verify its hash, and atomically move into place
        tmp_restore = orig_path.with_name(orig_path.name + ".restore.tmp")
        try:
            data = source_file.read_bytes()
            restored_data = bytes(b ^ XOR_KEY for b in data)
            tmp_restore.write_bytes(restored_data)
        except OSError as e:
            log.error(f"    I/O error during decryption staging of {orig_path.name}: {e}")
            safe_unlink_file(tmp_restore, "temporary restore file")
            error_count += 1
            continue

        # 5. Verify restored hash on temporary staging file
        actual_restored_hash = sha256_file(tmp_restore)
        if actual_restored_hash != expected_orig_hash:
            log.error(f"    HASH MISMATCH after decryption of {orig_path.name}!")
            log.error(f"      Expected (pre-sim): {expected_orig_hash}")
            log.error(f"      Actual (restored):  {actual_restored_hash}")
            safe_unlink_file(tmp_restore, "temporary restore file")
            hash_failures.append(str(orig_path))
            error_count += 1
            continue

        # 6. Atomic move temporary restore file to original path (no-replace)
        try:
            if orig_path.exists():
                raise FileExistsError(f"Original destination {orig_path.name} appeared during restore.")
            tmp_restore.rename(orig_path)
        except (FileExistsError, OSError) as e:
            log.error(f"    Failed to move restored file into destination {orig_path.name}: {e}")
            safe_unlink_file(tmp_restore, "temporary restore file")
            error_count += 1
            continue

        # 7. Only delete the encrypted source file after original is verified and in place
        if not safe_unlink_file(source_file, f"restored source file {source_file.name}"):
            error_count += 1

        if staged_path and staged_path.exists() and staged_path != source_file:
            staged_hash = sha256_file(staged_path)
            if staged_hash == expected_enc_hash:
                if not safe_unlink_file(staged_path, f"verified staging file {staged_path.name}"):
                    error_count += 1
            else:
                log.error(f"    SAFETY: Hash mismatch on orphaned staging file {staged_path.name}! Preserving file.")
                log.error(f"      Expected (encrypted): {expected_enc_hash}")
                log.error(f"      Actual on disk:       {staged_hash}")
                forensic_anomalies.append(f"Orphaned staging file {staged_path.name} (hash mismatch; preserved)")
                error_count += 1

        log.info(f"    Restored and verified: {orig_path.name} (SHA-256 matches pre-sim)")
        restored_count += 1

    # Only remove ransom note, simulation log, and journal if ALL restorations succeeded
    # AND zero forensic anomalies or preserved tampered files were detected.
    # If any error occurred or forensic evidence was preserved, retain all artifacts
    # so the state can be thoroughly investigated.
    if error_count == 0 and not forensic_anomalies:
        cleanup_targets = [
            run_dir / RANSOM_NOTE_FILENAME,
            run_dir / "simulation_log.txt",
            run_dir / "recovery_journal.json",
        ]
        for p in cleanup_targets:
            if not safe_unlink_file(p, f"simulation artifact {p.name}"):
                error_count += 1
                log.warning(f"  [RESTORE] Halting artifact cleanup: {p.name} could not be removed. Preserving remaining evidence.")
                break
    else:
        if forensic_anomalies and error_count == 0:
            log.warning("[RESTORE] Forensic anomalies / tampered artifacts preserved despite successful file restoration:")
            for fa in forensic_anomalies:
                log.warning(f"  Evidence: {fa}")
            log.warning("  PRESERVING recovery journal, ransom note, and simulation log for forensic investigation.")
        else:
            log.warning("[RESTORE] Skipping cleanup of ransom note, journal, and log — errors occurred.")
            log.warning("  Artifacts preserved for investigation. Fix errors and re-run --restore.")

    # Remove the run directory ONLY if it is truly empty.
    # Directory enumeration itself can fail on Windows, so it must
    # be protected just like rmdir().
    try:
        remaining_entries = list(run_dir.iterdir())
    except FileNotFoundError:
        # The directory is already absent; there is nothing left to remove.
        log.info(f"[RESTORE] Run directory is already absent: {run_dir}")
    except OSError as e:
        log.warning(
            f"[RESTORE] Could not inspect run directory {run_dir}: {e}"
        )
        error_count += 1
    else:
        if not remaining_entries:
            try:
                run_dir.rmdir()
                log.info(f"[RESTORE] Empty run directory removed: {run_dir}")
            except OSError as e:
                log.warning(
                    f"[RESTORE] Could not remove empty run directory "
                    f"{run_dir}: {e}"
                )
                error_count += 1
        else:
            log.info(f"[RESTORE] Run directory not empty, preserved: {run_dir}")
            for remaining in remaining_entries:
                log.info(f"  Remaining: {remaining.name}")

    # Keep the final summary AFTER all cleanup attempts.
    log.info("=" * 65)
    log.info(
        f"[RESTORE] Complete — Restored: {restored_count} | Errors: {error_count}"
    )
    if hash_failures:
        log.error(f"[RESTORE] Hash verification failures: {hash_failures}")
    return error_count


# ===========================================================================
# PHASE 1: TARGET SETUP — unique run directory, refuse non-empty (P0, Finding 2)
# ===========================================================================

def create_run_directory(base_dir: str, sim_id_short: str, dry_run: bool) -> Path:
    """
    Create a unique run-specific child directory: <base_dir>/<sim_id_short>/

    Refuses to run if the base directory already contains any files,
    preventing accidental encryption of pre-existing content.
    """
    base = enforce_safety_boundary(Path(base_dir))

    # Check: if base dir exists AND contains files, abort
    if base.exists():
        existing_files = [f for f in base.rglob("*") if f.is_file()]
        if existing_files:
            log.critical("=" * 65)
            log.critical("SAFETY ABORT: Target base directory is not empty.")
            log.critical(f"  Directory: {base}")
            log.critical(f"  Existing files: {len(existing_files)}")
            for f in existing_files[:5]:
                log.critical(f"    {f.relative_to(base)}")
            if len(existing_files) > 5:
                log.critical(f"    ... and {len(existing_files) - 5} more")
            log.critical("Remove or restore existing files before running a new simulation.")
            log.critical("To restore a previous run: python custom_behavior_sim.py --restore --manifest <path>")
            log.critical("=" * 65)
            sys.exit(1)

    # Create unique run subdirectory
    run_dir = base / sim_id_short
    if not dry_run:
        run_dir.mkdir(parents=True, exist_ok=False)
        log.info(f"[SETUP] Run directory created: {run_dir}")
    else:
        log.info(f"[DRY-RUN] Would create run directory: {run_dir}")

    return run_dir


def create_test_files(run_dir: Path, dry_run: bool) -> list:
    """
    Create 8 clearly-labelled dummy files in the run directory.
    Returns records for the artifact manifest.

    Note: dummy files are not valid Office/PDF/image documents.
    They are artificial byte sequences with matching extensions.
    This is documented as a known limitation. Acceptable for file-modification
    and timeline forensic analysis; not for document parser testing.
    """
    dummy_files = {
        "financial_report_Q3.xlsx":  b"[SIM-XLSX] Revenue:$1200000|Expenses:$800000|Net:$400000",
        "employee_database.csv":     b"[SIM-CSV] Name,Email,Dept\nAlice,alice@corp.com,Eng\nBob,bob@corp.com,HR",
        "executive_memo.docx":       b"[SIM-DOCX] FROM:CEO TO:All RE:Q4Strategy CONFIDENTIAL",
        "customer_list.txt":         b"[SIM-TXT] CustomerIDs:10001,10002,10003,10004,10005",
        "backup_keys.txt":           b"[SIM-TXT] BackupEncryptionKeys:(SIMULATION ONLY)",
        "project_proposal.pdf":      b"[SIM-PDF] ProjectAlpha Phase1 Deliverables Confidential",
        "logo.png":                  b"[SIM-PNG] \x89PNG\r\n\x1a\nSIMULATION IMAGE",
        "contract_draft.docx":       b"[SIM-DOCX] Agreement between PartyA and PartyB Draft v3",
    }

    log.info(f"[PHASE 1] Creating test files in: {run_dir}")
    created = []

    for filename, content in dummy_files.items():
        filepath = run_dir / filename
        if not dry_run:
            filepath.write_bytes(content)
            pre_hash = sha256_file(filepath)
            ts = file_timestamps(filepath)
        else:
            pre_hash = hashlib.sha256(content).hexdigest()
            ts = {"dry_run": True}

        log.info(f"  {'[DRY-RUN] Would create' if dry_run else 'Created'}: {filename} | SHA-256: {pre_hash[:16]}...")
        created.append({
            "filename": filename,
            "path": str(filepath),
            "pre_sim_sha256": pre_hash,
            "pre_sim_timestamps": ts,
        })
        if not dry_run:
            time.sleep(0.12)  # Spread creation timestamps for richer timeline

    log.info(f"[PHASE 1] {len(created)} test files {'would be ' if dry_run else ''}created.")
    return created


# ===========================================================================
# PHASE 2: FILE DISCOVERY (T1083) — confined to run_dir only
# ===========================================================================

def enumerate_run_files(run_dir: Path, created_records: list, dry_run: bool) -> list:
    """
    Build the encryption target list from ONLY the files created by this run.

    v1.2 change: Does NOT call rglob() on the run directory and discover
    pre-existing files. Instead, it uses the exact list returned by
    create_test_files() and verifies each file exists.

    This guarantees the encryption scope is strictly limited to the 8
    files created moments ago — not any pre-existing content.
    """
    log.info(f"[PHASE 2] T1083 — Enumerating THIS run's target files in: {run_dir}")
    targets = []

    for rec in created_records:
        fp = Path(rec["path"])
        if dry_run:
            log.info(f"  [DRY-RUN] Would target: {fp.name}")
            targets.append(fp)
        elif fp.exists() and fp.suffix in TARGET_EXTENSIONS:
            log.info(f"  Confirmed target: {fp.name}")
            targets.append(fp)
        else:
            log.warning(f"  Expected file not found: {fp.name} — skipping")

    log.info(f"[PHASE 2] {len(targets)} files confirmed as encryption targets.")
    return targets


# ===========================================================================
# PHASE 3: T1490 COMMANDS
# ===========================================================================

def simulate_t1490(live: bool, skip: bool, dry_run: bool) -> list:
    """
    T1490 — Inhibit System Recovery.

    Modes:
      dry_run=True        → Print only, no subprocess, no log entry
      skip=True           → Skip entirely (not logged)
      live=False (default) → Log command as an attempted artifact WITHOUT executing
      live=True           → Actually execute subprocess (requires --live-t1490)

    Forensic note on default mode:
      Logging the command without executing it does NOT generate Event 4688,
      Prefetch, or process-tree memory artifacts. Those artifacts require --live-t1490.
      The trade-off is that default mode makes no Windows system state changes,
      which is safer for first-time execution.
    """
    if skip:
        log.info("[PHASE 3] --skip-t1490 set. T1490 commands not logged or executed.")
        return []

    commands = [
        {
            "technique": "T1490",
            "description": "Delete Volume Shadow Copies (inhibit recovery)",
            "command": ["vssadmin", "delete", "shadows", "/all", "/quiet"],
        },
        {
            "technique": "T1490",
            "description": "Disable Windows Recovery Environment",
            "command": ["bcdedit", "/set", "{default}", "recoveryenabled", "No"],
        },
    ]

    records = []
    for cmd_info in commands:
        cmd_str = " ".join(cmd_info["command"])
        record = {
            "technique": cmd_info["technique"],
            "description": cmd_info["description"],
            "command_string": cmd_str,
            "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            "execution_mode": None,
            "exit_code": None,
            "stdout": None,
            "stderr": None,
        }

        if dry_run:
            record["execution_mode"] = "dry_run"
            record["exit_code"] = "DRY_RUN_NOT_EXECUTED"
            log.info(f"[DRY-RUN] Would attempt T1490: {cmd_str}")

        elif not live:
            # Default safe mode: log the command as an artifact without executing
            record["execution_mode"] = "logged_only"
            record["exit_code"] = "LOGGED_NOT_EXECUTED"
            log.info(f"[PHASE 3] T1490 command recorded (NOT executed — use --live-t1490 to execute):")
            log.info(f"  Command: {cmd_str}")
            log.info(f"  Forensic note: No Event 4688 or Prefetch artifact generated in this mode.")

        else:
            # --live-t1490 mode: actually execute
            record["execution_mode"] = "live_executed"
            log.info(f"[PHASE 3] [LIVE] Executing T1490: {cmd_str}")
            try:
                result = subprocess.run(
                    cmd_info["command"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    shell=False,
                )
                record["exit_code"] = result.returncode
                record["stdout"] = result.stdout.strip() or "(empty)"
                record["stderr"] = result.stderr.strip() or "(empty)"
                log.info(f"  Exit code: {result.returncode}")
                log.info(f"  stdout: {record['stdout']}")
            except FileNotFoundError:
                log.warning(f"  {cmd_info['command'][0]} not found — non-Windows VM?")
                record["exit_code"] = "NOT_FOUND"
            except subprocess.TimeoutExpired:
                log.warning(f"  {cmd_info['command'][0]} timed out.")
                record["exit_code"] = "TIMEOUT"

        records.append(record)

    return records


# ===========================================================================
# PHASE 4: XOR "ENCRYPTION" + RENAME (T1486) — FAILURE-SAFE STAGING & JOURNAL
# ===========================================================================

def append_recovery_journal(run_dir: Path, entry: dict, dry_run: bool) -> None:
    """
    Append a step to recovery_journal.json with atomic file replacement.
    Ensures that journal writes are crash-resilient and never ignored.
    """
    if dry_run:
        return
    journal_path = run_dir / "recovery_journal.json"
    tmp_journal_path = run_dir / f"recovery_journal_{uuid.uuid4().hex[:6]}.tmp"
    journal = []
    if journal_path.exists():
        try:
            with open(journal_path, "r", encoding="utf-8") as f:
                journal = json.load(f)
        except Exception as e:
            raise RuntimeError(f"Cannot read existing recovery journal {journal_path}: {e}")
    journal.append(entry)
    try:
        with open(tmp_journal_path, "w", encoding="utf-8") as f:
            json.dump(journal, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        tmp_journal_path.replace(journal_path)
    except Exception as e:
        safe_unlink_file(tmp_journal_path, "temporary journal file")
        raise RuntimeError(f"CRITICAL: Failed to write recovery journal {journal_path}: {e}. Aborting operation.")


def xor_encrypt_file(filepath: Path, run_dir: Path, dry_run: bool) -> dict:
    """
    Failure-safe XOR modification with staging and atomic replacement.

    Safety Guarantee:
    Original file is NEVER modified in-place.
    1. Read original content & calculate pre-modification SHA-256 hash.
    2. In-memory XOR encryption & calculate expected encrypted hash.
    3. Write XOR-encrypted content to a temporary staging file (.stage.tmp).
    4. Verify staging file exists, matches expected size, and verify staging hash == expected encrypted hash.
    5. Refuse if destination .locked file already exists (prevent accidental overwrite).
    6. Move staging file to final .locked destination.
    7. Verify final .locked file hash == expected encrypted hash.
    8. Only after BOTH hash comparisons pass, delete the original file.
    9. Record all state transitions atomically in recovery_journal.json.
    """
    pre_hash = sha256_file(filepath) if not dry_run else "DRY_RUN"
    pre_ts = file_timestamps(filepath) if not dry_run else {"dry_run": True}
    new_path = filepath.with_name(filepath.name + ENCRYPTED_EXTENSION)

    if not dry_run:
        staged_path = filepath.with_name(filepath.name + ".stage.tmp")
        append_recovery_journal(run_dir, {
            "original_path": str(filepath),
            "staged_path": str(staged_path),
            "target_path": str(new_path),
            "pre_modification_sha256": pre_hash,
            "status": "PENDING_STAGING",
            "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
        }, dry_run)

        try:
            data = filepath.read_bytes()
            encrypted = bytes(b ^ XOR_KEY for b in data)
            expected_enc_hash = hashlib.sha256(encrypted).hexdigest()

            staged_path.write_bytes(encrypted)

            if not staged_path.exists():
                raise OSError(f"Staged file {staged_path.name} was not created.")
            if staged_path.stat().st_size != len(data):
                raise OSError(f"Staged file size mismatch: expected {len(data)}, got {staged_path.stat().st_size}")

            # Verify staging file hash against independently calculated expected hash
            staged_hash = sha256_file(staged_path)
            if staged_hash != expected_enc_hash:
                raise ValueError(
                    f"Staged file SHA-256 verification failed for {filepath.name}! "
                    f"Expected: {expected_enc_hash}, Got: {staged_hash}"
                )

            append_recovery_journal(run_dir, {
                "original_path": str(filepath),
                "staged_path": str(staged_path),
                "target_path": str(new_path),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": staged_hash,
                "expected_sha256": expected_enc_hash,
                "status": "STAGED_VERIFIED",
                "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            }, dry_run)

            # Atomic no-replace move to destination
            # On Windows, Path.rename() maps to Win32 MoveFileExW without MOVEFILE_REPLACE_EXISTING,
            # which raises FileExistsError atomically if destination exists.
            if new_path.exists():
                raise FileExistsError(
                    f"Encrypted destination already exists: {new_path.name}. "
                    "Refusing to overwrite pre-existing destination."
                )

            try:
                staged_path.rename(new_path)
            except FileExistsError:
                raise FileExistsError(
                    f"Encrypted destination collision detected: {new_path.name}. "
                    "Atomic no-replace move refused overwrite."
                )

            if not new_path.exists():
                raise OSError(f"Final encrypted file {new_path.name} missing after rename.")

            # Verify final destination file hash against expected encrypted hash
            post_hash = sha256_file(new_path)
            if post_hash != expected_enc_hash:
                raise ValueError(
                    f"Final encrypted file SHA-256 verification failed for {new_path.name}! "
                    f"Expected: {expected_enc_hash}, Got: {post_hash}"
                )

            post_ts = file_timestamps(new_path)

            # Record PRE_UNLINK_COMMITTED state in recovery journal BEFORE deleting original.
            # Ensures crash recovery can restore even if a crash occurs during or immediately after unlink.
            append_recovery_journal(run_dir, {
                "original_path": str(filepath),
                "encrypted_path": str(new_path),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": post_hash,
                "status": "PRE_UNLINK_COMMITTED",
                "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            }, dry_run)

            # Both verification checks passed and journal committed: delete original file
            filepath.unlink()

            append_recovery_journal(run_dir, {
                "original_path": str(filepath),
                "encrypted_path": str(new_path),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": post_hash,
                "status": "COMMITTED",
                "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            }, dry_run)

        except Exception as e:
            safe_unlink_file(staged_path, "staging file")
            append_recovery_journal(run_dir, {
                "original_path": str(filepath),
                "target_path": str(new_path),
                "staged_path": str(staged_path),
                "pre_modification_sha256": pre_hash if 'pre_hash' in locals() else None,
                "post_modification_sha256": post_hash if 'post_hash' in locals() else (expected_enc_hash if 'expected_enc_hash' in locals() else None),
                "original_exists": filepath.exists(),
                "encrypted_exists": new_path.exists(),
                "status": "FAILED",
                "error": str(e),
                "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            }, dry_run)
            raise e
    else:
        post_hash = "DRY_RUN"
        post_ts = {"dry_run": True}

    return {
        "original_name": filepath.name,
        "encrypted_name": new_path.name,
        "original_path": str(filepath),
        "encrypted_path": str(new_path),
        "xor_key_hex": f"0x{XOR_KEY:02X}",
        "pre_modification_sha256": pre_hash,
        "post_modification_sha256": post_hash,
        "pre_modification_timestamps": pre_ts,
        "post_modification_timestamps": post_ts,
    }


def simulate_encryption(target_files: list, run_dir: Path, dry_run: bool, incremental_manifest: dict = None) -> tuple:
    """Apply XOR to all discovered files with atomic staging, per-file manifest update, and fault reporting."""
    log.info(f"[PHASE 4] T1486 — {'[DRY-RUN] Would encrypt' if dry_run else 'Encrypting'} {len(target_files)} files | XOR key: 0x{XOR_KEY:02X}")

    records = []
    failures = []
    for filepath in target_files:
        try:
            rec = xor_encrypt_file(filepath, run_dir, dry_run)
            records.append(rec)
            log.info(
                f"  {'[DRY-RUN] Would encrypt' if dry_run else 'Encrypted'}: "
                f"{rec['original_name']} -> {rec['encrypted_name']} "
                f"| Pre: {rec['pre_modification_sha256'][:16]}... "
                f"| Post: {rec['post_modification_sha256'][:16]}..."
            )
            # Finding 4 fix: update manifest on disk atomically after each file
            if incremental_manifest is not None and not dry_run:
                incremental_manifest["phase_4_encrypted_files"] = list(records)
                incremental_manifest["status"] = "IN_PROGRESS"
                write_manifest(incremental_manifest, run_dir, dry_run=False)

            if not dry_run:
                time.sleep(0.05)
        except Exception as e:
            log.error(f"  [PHASE 4] FAILED: {filepath.name}: {e}")
            enc_target = filepath.with_name(filepath.name + ENCRYPTED_EXTENSION)
            failures.append({
                "original_name": filepath.name,
                "original_path": str(filepath),
                "encrypted_path": str(enc_target),
                "original_exists": filepath.exists(),
                "encrypted_exists": enc_target.exists(),
                "error": str(e),
                "timestamp_utc": datetime.now(tz=timezone.utc).isoformat(),
            })

    log.info(f"[PHASE 4] Completed: {len(records)} encrypted | {len(failures)} failed.")
    return records, failures


# ===========================================================================
# PHASE 5: RANSOM NOTE
# ===========================================================================

def drop_ransom_note(run_dir: Path, sim_id: str, dry_run: bool) -> dict:
    """Drop a clearly-marked fake ransom note. Creation timestamp anchors T-end."""
    note_path = run_dir / RANSOM_NOTE_FILENAME

    note_content = f"""\
================================================================================
                        YOUR FILES HAVE BEEN ENCRYPTED
================================================================================

[SIMULATION — CONTROLLED DFIR LAB EXERCISE — NOT REAL RANSOMWARE]
[Script: custom_behavior_sim.py v1.2.12 | Simulation ID: {sim_id}]
[Operator: Yogesh T | All changes confined to: {run_dir}]

--------------------------------------------------------------------------------
All your important files have been encrypted.
To recover your files:
  1. Pay 0.5 BTC to: [SIMULATED: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2]
  2. Email: [SIMULATED: recovery@darkweb-simulation.invalid]
  3. You have 72 hours.

Your unique victim ID: {sim_id}

--------------------------------------------------------------------------------
                     [END OF SIMULATION — NO REAL HARM DONE]
Simulation timestamp: {datetime.now(tz=timezone.utc).isoformat()}
================================================================================
"""
    if not dry_run:
        note_path.write_text(note_content, encoding="utf-8")
        ts = file_timestamps(note_path)
        note_hash = sha256_file(note_path)
        log.info(f"[PHASE 5] Ransom note dropped: {note_path}")
        log.info(f"  SHA-256: {note_hash}")
    else:
        ts = {"dry_run": True}
        note_hash = "DRY_RUN"
        log.info(f"[DRY-RUN] Would drop ransom note: {note_path}")

    return {
        "path": str(note_path),
        "sha256": note_hash,
        "timestamps": ts,
        "simulation_id": sim_id,
    }


# ===========================================================================
# ARTIFACT MANIFEST
# ===========================================================================

def write_manifest(manifest: dict, run_dir: Path, dry_run: bool) -> str:
    """Write the JSON artifact manifest to the run directory with atomic replacement."""
    manifest_path = run_dir / "artifact_manifest.json"

    if not dry_run:
        tmp_path = run_dir / f"artifact_manifest_{uuid.uuid4().hex[:6]}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        tmp_path.replace(manifest_path)
        manifest_hash = sha256_file(manifest_path)
        log.info(f"[MANIFEST] Written: {manifest_path} (status: {manifest.get('status', 'N/A')})")
        log.info(f"[MANIFEST] SHA-256: {manifest_hash}")
        return str(manifest_path)
    else:
        log.info(f"[DRY-RUN] Would write manifest: {manifest_path}")
        return str(manifest_path)


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    args = parse_args()
    sim_id = str(uuid.uuid4()).upper()
    sim_id_short = sim_id.split("-")[0]  # First 8 chars for directory name
    sim_start = datetime.now(tz=timezone.utc)

    is_dry_run = args.dry_run

    # Determine run directory path early (needed for log file)
    run_dir_path = Path(BASE_TARGET_DIR) / sim_id_short

    # --- Handle restore mode before setting up logging ---
    if args.restore:
        # Minimal logging setup before restore (log to stdout only)
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
        target_path = args.manifest or args.journal
        error_count = restore_mode(target_path)
        sys.exit(0 if error_count == 0 else 1)

    # --- Setup stdout-only logging first (before confirmation) ---
    # FileHandler is added only AFTER confirmation to avoid creating the run
    # directory and log file before the operator has agreed to proceed.
    setup_logging(Path(os.devnull))  # stdout only at this stage

    # --- Dry-run banner ---
    if is_dry_run:
        log.warning("=" * 65)
        log.warning("[DRY-RUN MODE] No filesystem changes will be made.")
        log.warning("All operations are printed only. Zero artifacts generated.")
        log.warning("=" * 65)

    # --- live-t1490 warning ---
    if args.live_t1490:
        log.warning("=" * 65)
        log.warning("[--live-t1490 ACTIVE]")
        log.warning("vssadmin and bcdedit WILL be executed.")
        log.warning("Windows recovery configuration WILL be modified.")
        log.warning("Ensure the VM snapshot is current before proceeding.")
        log.warning("=" * 65)

    # --- Safety boundary ---
    enforce_safety_boundary(Path(BASE_TARGET_DIR))

    # --- Simulation context ---
    proc_ctx = simulation_process_context()
    log.info(f"[META] PID: {proc_ctx['pid']} | PPID: {proc_ctx['ppid']} | Parent: {proc_ctx['parent_process_name']}")

    # --- STEP 1: Unconditional live-T1490 gate ---
    # This prompt is ALWAYS required when --live-t1490 is set.
    # --yes CANNOT bypass it. This is enforced by placing it outside
    # the `if not args.yes` block.
    if args.live_t1490:
        print("\n" + "=" * 65)
        print("[LIVE T1490 GATE] vssadmin + bcdedit WILL execute.")
        print("Windows shadow copies and recovery configuration WILL be modified.")
        print("This prompt cannot be bypassed by --yes.")
        print("=" * 65)
        confirm_live = input("Type 'EXECUTE-LIVE-T1490' to confirm (case-sensitive): ")
        if confirm_live != "EXECUTE-LIVE-T1490":
            log.info("[GATE] Live T1490 not confirmed. Aborting.")
            sys.exit(0)
        log.info("[GATE] Live T1490 confirmed by operator.")

    # --- STEP 2: General confirmation (skippable with --yes) ---
    if not args.yes:
        mode_desc = (
            "DRY-RUN (no changes)" if is_dry_run else
            "--skip-t1490 (file ops only, T1490 skipped)" if args.skip_t1490 else
            "--live-t1490 (vssadmin + bcdedit confirmed above)" if args.live_t1490 else
            "DEFAULT SAFE (file ops + T1490 logged, not executed)"
        )
        print("\n" + "=" * 65)
        print(f"SIMULATION v1.2.12  |  ID: {sim_id}")
        print(f"Mode:      {mode_desc}")
        print(f"Run dir:   {run_dir_path}")
        print(f"Platform:  {platform.platform()}")
        print("=" * 65)
        confirm = input("\nType 'CONFIRM' to proceed (case-sensitive): ")
        if confirm != "CONFIRM":
            log.info("Simulation aborted by operator.")
            sys.exit(0)

    # --- Pre-run safety check: Verify base directory BEFORE creating run dir ---
    base = Path(BASE_TARGET_DIR)
    if base.exists():
        existing_files = [f for f in base.rglob("*") if f.is_file()]
        if existing_files:
            log.critical("=" * 65)
            log.critical("SAFETY ABORT: Base target directory contains pre-existing files.")
            log.critical(f"  Found {len(existing_files)} file(s) in {BASE_TARGET_DIR}:")
            for f in existing_files[:5]:
                log.critical(f"  {f}")
            log.critical("Remove or restore them before running a new simulation.")
            log.critical("=" * 65)
            sys.exit(1)

    if run_dir_path.exists():
        log.critical("=" * 65)
        log.critical(f"SAFETY ABORT: Run directory already exists: {run_dir_path}")
        log.critical("Refusing to reuse an existing run directory.")
        log.critical("=" * 65)
        sys.exit(1)

    # --- Create run directory with exist_ok=False and add file log handler AFTER check ---
    if not is_dry_run:
        try:
            base.mkdir(parents=True, exist_ok=True)
            run_dir_path.mkdir(parents=False, exist_ok=False)
        except (FileExistsError, OSError) as e:
            log.critical(f"SAFETY ABORT: Failed to create run directory {run_dir_path}: {e}")
            sys.exit(1)

        log_file = run_dir_path / "simulation_log.txt"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%dT%H:%M:%S"
        ))
        logging.getLogger().addHandler(fh)
        log.info(f"[LOGGING] File handler active: {log_file}")
    else:
        log_file = None

    log.info("=" * 65)
    log.info(f"SIMULATION START | v1.2.12 | ID: {sim_id} | {sim_start.isoformat()}")
    log.info("=" * 65)

    run_dir = run_dir_path

    # --- Phase 1: Create test files ---
    created_records = create_test_files(run_dir, is_dry_run)
    if not is_dry_run:
        time.sleep(1)

    # --- Phase 2: Enumerate THIS run's files only ---
    target_files = enumerate_run_files(run_dir, created_records, is_dry_run)
    if not is_dry_run:
        time.sleep(0.5)

    # --- Phase 3: T1490 ---
    t1490_records = simulate_t1490(
        live=args.live_t1490,
        skip=args.skip_t1490,
        dry_run=is_dry_run,
    )
    if not is_dry_run:
        time.sleep(0.5)

    # --- Write incremental pre-encryption manifest for dual-redundancy crash recovery ---
    if not is_dry_run:
        incremental_manifest = {
            "simulation_id": sim_id,
            "sim_id_short": sim_id_short,
            "version": "1.2.12",
            "status": "IN_PROGRESS_PRE_ENCRYPTION",
            "operator": "Yogesh T",
            "start_utc": sim_start.isoformat(),
            "mode": (
                "dry_run" if is_dry_run else
                "skip_t1490" if args.skip_t1490 else
                "live_t1490" if args.live_t1490 else
                "default_safe"
            ),
            "platform": platform.platform(),
            "run_directory": str(run_dir),
            "phase_1_files_created": created_records,
            "phase_3_t1490_commands": t1490_records,
            "phase_4_encrypted_files": [],
        }
        write_manifest(incremental_manifest, run_dir, is_dry_run)
    else:
        incremental_manifest = None

    # --- Phase 4: XOR encryption (staged, failure-safe, per-file manifest update) ---
    encryption_records, failed_records = simulate_encryption(target_files, run_dir, is_dry_run, incremental_manifest)
    if not is_dry_run:
        time.sleep(0.5)

    # If any file failed encryption, record failure manifest and abort immediately
    if failed_records:
        sim_end = datetime.now(tz=timezone.utc)
        log.critical("=" * 65)
        log.critical(f"SIMULATION FAILED: {len(failed_records)} file(s) failed during Phase 4 encryption!")
        for f_rec in failed_records:
            log.critical(f"  Failed: {f_rec['original_name']} — Error: {f_rec['error']}")
        log.critical("Recovery journal and failure manifest preserved for forensic analysis.")
        log.critical("=" * 65)

        failure_manifest = {
            "simulation_id": sim_id,
            "sim_id_short": sim_id_short,
            "version": "1.2.12",
            "status": "FAILED",
            "operator": "Yogesh T",
            "start_utc": sim_start.isoformat(),
            "end_utc": sim_end.isoformat(),
            "duration_seconds": (sim_end - sim_start).total_seconds(),
            "mode": (
                "dry_run" if is_dry_run else
                "skip_t1490" if args.skip_t1490 else
                "live_t1490" if args.live_t1490 else
                "default_safe"
            ),
            "platform": platform.platform(),
            "run_directory": str(run_dir),
            "phase_1_files_created": created_records,
            "phase_3_t1490_commands": t1490_records,
            "phase_4_encrypted_files": encryption_records,
            "phase_4_encryption_failures": failed_records,
        }
        write_manifest(failure_manifest, run_dir, is_dry_run)
        sys.exit(1)

    # --- Phase 5: Ransom note ---
    note_record = drop_ransom_note(run_dir, sim_id, is_dry_run)

    # --- Build and write manifest ---
    sim_end = datetime.now(tz=timezone.utc)
    manifest = {
        "simulation_id": sim_id,
        "sim_id_short": sim_id_short,
        "version": "1.2.12",
        "status": "SUCCESS",
        "operator": "Yogesh T",
        "start_utc": sim_start.isoformat(),
        "end_utc": sim_end.isoformat(),
        "duration_seconds": (sim_end - sim_start).total_seconds(),
        "mode": (
            "dry_run" if is_dry_run else
            "skip_t1490" if args.skip_t1490 else
            "live_t1490" if args.live_t1490 else
            "default_safe"
        ),
        "platform": platform.platform(),
        "python_version": sys.version,
        "simulation_process_context": proc_ctx,
        "base_target_dir": BASE_TARGET_DIR,
        "run_directory": str(run_dir),
        "xor_key_hex": f"0x{XOR_KEY:02X}",
        "mitre_techniques": ["T1083", "T1486", "T1490"],
        "mitre_notes": {
            "T1083": "File enumeration confined to run directory",
            "T1486": "XOR modification + .locked rename — reversible simulation",
            "T1490": f"Commands {'executed live' if args.live_t1490 else 'logged only (default safe mode)' if not is_dry_run else 'dry-run only'}",
            "T1057": "NOT claimed — process metadata captures simulation context only, not system process enumeration",
        },
        "known_limitations": [
            "Dummy files are not valid Office/PDF/image documents (byte sequences with matching extensions)",
            "T1490 forensic artifacts (Event 4688, Prefetch) only generated in --live-t1490 mode",
        ],
        "phase_1_files_created": created_records,
        "phase_3_t1490_commands": t1490_records,
        "phase_4_encrypted_files": encryption_records,
        "phase_5_ransom_note": note_record,
    }
    manifest_path = write_manifest(manifest, run_dir, is_dry_run)

    # --- Final summary ---
    duration = (sim_end - sim_start).total_seconds()
    log.info("=" * 65)
    log.info("SIMULATION COMPLETE")
    log.info(f"  ID       : {sim_id}")
    log.info(f"  Mode     : {manifest['mode']}")
    log.info(f"  Duration : {duration:.2f}s")
    log.info(f"  Run dir  : {run_dir}")
    log.info(f"  Created  : {len(created_records)} files")
    log.info(f"  Encrypted: {len(encryption_records)} files")
    log.info(f"  T1490    : {len(t1490_records)} commands recorded")
    log.info(f"  Note     : {note_record['path']}")
    log.info(f"  Manifest : {manifest_path}")
    if not is_dry_run:
        log.info(f"  Log file : {log_file}")
    log.info("=" * 65)

    if not is_dry_run:
        log.info("")
        log.info("NEXT STEPS — DO THIS NOW:")
        log.info("  1. DO NOT restart or revert the VM.")
        log.info("  2. Screenshot the terminal output (shows simulation complete + ID).")
        log.info("  3. Capture memory dump: forensics/acquisition/memory_dump_steps.md")
        log.info("  4. Capture disk image:  forensics/acquisition/disk_image_steps.md")
        log.info("  5. ONLY THEN revert VM to baseline snapshot.")
        log.info(f"  6. To restore: py custom_behavior_sim.py --restore --manifest {manifest_path}")
        log.info("=" * 65)


if __name__ == "__main__":
    main()
