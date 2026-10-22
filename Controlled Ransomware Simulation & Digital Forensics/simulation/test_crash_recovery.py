#!/usr/bin/env python3
"""
test_crash_recovery.py
======================
Unit & Integration Test Suite for custom_behavior_sim.py v1.2.12 Crash Recovery.
Tests all 15 positive and negative failure/interruption scenarios using isolated disposable files.
"""

import sys
import shutil
import hashlib
import tempfile
import unittest
from pathlib import Path

# Add simulation directory to path
SIM_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SIM_DIR))

import custom_behavior_sim as sim

XOR_KEY = sim.XOR_KEY


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestCrashRecoveryScenarios(unittest.TestCase):
    def setUp(self):
        # Create an isolated temporary test sandbox inside Public or system temp
        self.test_dir = Path(tempfile.mkdtemp(prefix="dfir_recovery_test_"))
        self.run_dir = self.test_dir / "RUN001"
        self.run_dir.mkdir(parents=True)
        # Patch approved directories to include test_dir for test execution
        sim.SAFE_PARENT_DIRS.append(Path(self.test_dir))

    def tearDown(self):
        if Path(self.test_dir) in sim.SAFE_PARENT_DIRS:
            sim.SAFE_PARENT_DIRS.remove(Path(self.test_dir))
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scenario_1_crash_after_staged_verified_before_rename(self):
        """Scenario 1: Crash after STAGED_VERIFIED, before rename.
        Original exists intact, staging file exists, .locked does not exist.
        Expected: Intact original preserved; orphaned staging file cleaned up.
        """
        orig = self.run_dir / "doc1.txt"
        orig_content = b"Financial Q3 Report Confidential"
        orig.write_bytes(orig_content)
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        staged = self.run_dir / "doc1.txt.stage.tmp"
        staged.write_bytes(enc_content)

        target = self.run_dir / "doc1.txt.locked"

        # Journal has PENDING_STAGING then STAGED_VERIFIED with pre_hash
        journal = [
            {
                "original_path": str(orig),
                "staged_path": str(staged),
                "target_path": str(target),
                "pre_modification_sha256": pre_hash,
                "status": "PENDING_STAGING",
            },
            {
                "original_path": str(orig),
                "staged_path": str(staged),
                "target_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "expected_sha256": enc_hash,
                "status": "STAGED_VERIFIED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        import json
        journal_file.write_text(json.dumps(journal, indent=2))

        # Run restore_mode
        sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists(), "Original file must exist")
        self.assertEqual(orig.read_bytes(), orig_content, "Original content must be intact")
        self.assertFalse(staged.exists(), "Orphaned staging file must be cleaned up")
        self.assertFalse(target.exists(), "Target .locked file must not exist")

    def test_scenario_2_crash_after_rename_before_pre_unlink(self):
        """Scenario 2: Crash after rename, before pre-unlink journal entry.
        Original exists, .locked exists, staging gone.
        Expected: Original preserved; orphaned .locked file cleaned up.
        """
        orig = self.run_dir / "doc2.txt"
        orig_content = b"HR Employee Records"
        orig.write_bytes(orig_content)
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc2.txt.locked"
        target.write_bytes(enc_content)

        journal = [
            {
                "original_path": str(orig),
                "staged_path": str(self.run_dir / "doc2.txt.stage.tmp"),
                "target_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "STAGED_VERIFIED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        import json
        journal_file.write_text(json.dumps(journal, indent=2))

        sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists())
        self.assertEqual(orig.read_bytes(), orig_content)
        self.assertFalse(target.exists(), "Orphaned .locked file must be cleaned up")

    def test_scenario_3_crash_after_pre_unlink_committed_before_unlink(self):
        """Scenario 3: Crash after PRE_UNLINK_COMMITTED, before unlink.
        Original exists, .locked exists, journal has PRE_UNLINK_COMMITTED.
        Expected: Original preserved; orphaned .locked file cleaned up.
        """
        orig = self.run_dir / "doc3.txt"
        orig_content = b"Network Architecture Diagram Data"
        orig.write_bytes(orig_content)
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc3.txt.locked"
        target.write_bytes(enc_content)

        journal = [
            {
                "original_path": str(orig),
                "encrypted_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "PRE_UNLINK_COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        import json
        journal_file.write_text(json.dumps(journal, indent=2))

        sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists())
        self.assertEqual(orig.read_bytes(), orig_content)
        self.assertFalse(target.exists())

    def test_scenario_4_crash_after_unlink_before_committed(self):
        """Scenario 4: Crash after unlink, before COMMITTED journal write.
        Original is unlinked (missing), .locked exists, journal has PRE_UNLINK_COMMITTED.
        Expected: Original successfully restored with exact pre-hash; .locked deleted.
        """
        orig = self.run_dir / "doc4.txt"
        orig_content = b"Kerberos Golden Ticket Analysis Notes"
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc4.txt.locked"
        target.write_bytes(enc_content)

        journal = [
            {
                "original_path": str(orig),
                "encrypted_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "PRE_UNLINK_COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        import json
        journal_file.write_text(json.dumps(journal, indent=2))

        sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists(), "Original must be restored")
        self.assertEqual(orig.read_bytes(), orig_content, "Restored content must match")
        self.assertFalse(target.exists(), ".locked file must be removed after verified restore")

    def test_scenario_5_incomplete_manifest_auto_fallback(self):
        """Scenario 5: Incomplete manifest with valid journal.
        Manifest has status 'IN_PROGRESS_PRE_ENCRYPTION', journal has COMMITTED entry.
        Expected: Automatic fallback to journal, original restored.
        """
        orig = self.run_dir / "doc5.txt"
        orig_content = b"Executive Passwords Backup"
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc5.txt.locked"
        target.write_bytes(enc_content)

        # Incomplete manifest
        manifest = {
            "simulation_id": "TEST-INCOMPLETE",
            "version": "1.2.7",
            "status": "IN_PROGRESS_PRE_ENCRYPTION",
            "run_directory": str(self.run_dir),
            "phase_4_encrypted_files": []
        }
        manifest_file = self.run_dir / "artifact_manifest.json"
        import json
        manifest_file.write_text(json.dumps(manifest, indent=2))

        # Complete journal
        journal = [
            {
                "original_path": str(orig),
                "encrypted_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text(json.dumps(journal, indent=2))

        # Pass manifest path to restore_mode
        sim.restore_mode(str(manifest_file))

        self.assertTrue(orig.exists())
        self.assertEqual(orig.read_bytes(), orig_content)
        self.assertFalse(target.exists())

    def test_scenario_6_failed_entry_carries_forward_hashes(self):
        """Scenario 6: File has PRE_UNLINK_COMMITTED followed by FAILED entry.
        Original was unlinked, .locked exists, FAILED is latest status.
        Expected: Hashes carried forward; .locked decrypted and original restored.
        """
        orig = self.run_dir / "doc6.txt"
        orig_content = b"Customer Master Key Data"
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc6.txt.locked"
        target.write_bytes(enc_content)

        journal = [
            {
                "original_path": str(orig),
                "encrypted_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "PRE_UNLINK_COMMITTED",
            },
            {
                "original_path": str(orig),
                "target_path": str(target),
                "original_exists": False,
                "encrypted_exists": True,
                "status": "FAILED",
                "error": "Simulated I/O failure during committed journal write",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        import json
        journal_file.write_text(json.dumps(journal, indent=2))

        sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists())
        self.assertEqual(orig.read_bytes(), orig_content)
        self.assertFalse(target.exists())

    def test_scenario_7_destination_collision_refused(self):
        """Scenario 7: Encrypted destination already exists.
        Expected: FileExistsError raised; original left 100% untouched.
        """
        orig = self.run_dir / "doc7.txt"
        orig_content = b"Pre-existing original data"
        orig.write_bytes(orig_content)

        # Pre-create the .locked target file
        target = self.run_dir / "doc7.txt.locked"
        target.write_bytes(b"Pre-existing alien locked file")

        with self.assertRaises(FileExistsError):
            sim.xor_encrypt_file(orig, self.run_dir, dry_run=False)

        self.assertEqual(orig.read_bytes(), orig_content, "Original must be untouched")
        self.assertEqual(target.read_bytes(), b"Pre-existing alien locked file", "Pre-existing destination must not be overwritten")

    def test_scenario_8_corrupt_recovery_journal_during_incomplete_manifest_fallback(self):
        """Scenario 8: Corrupt or unreadable recovery journal during incomplete manifest fallback.
        Expected: SystemExit(1) safe abort; no partial or unsafe restore performed.
        """
        import json
        manifest_file = self.run_dir / "artifact_manifest.json"
        manifest_file.write_text(json.dumps({
            "simulation_id": "TEST008",
            "status": "IN_PROGRESS_PRE_ENCRYPTION",
            "phase_4_encrypted_files": []
        }))

        # Write corrupt/invalid JSON to recovery journal
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text("{CORRUPT_INVALID_JSON: [}")

        with self.assertRaises(SystemExit) as cm:
            sim.restore_mode(str(manifest_file))
        self.assertEqual(cm.exception.code, 1)

    def test_scenario_9_tampered_locked_file_with_intact_staging(self):
        """Scenario 9: Primary .locked file is corrupted/tampered, but .stage.tmp is intact.
        Expected: Fall back to verified staging file, restore original with exact pre-hash,
        preserve the tampered .locked file for forensic inspection.
        """
        import json
        orig = self.run_dir / "doc9.txt"
        orig_content = b"Financial Q4 Forecast Original"
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        # Staged file is intact with correct XOR bytes
        staged = self.run_dir / "doc9.txt.stage.tmp"
        staged.write_bytes(enc_content)

        # Primary .locked file is corrupted/tampered
        target = self.run_dir / "doc9.txt.locked"
        target.write_bytes(b"TAMPERED_OR_CORRUPT_BYTES")

        journal = [
            {
                "original_path": str(orig),
                "staged_path": str(staged),
                "target_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text(json.dumps(journal, indent=2))

        error_count = sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists(), "Original file must be restored")
        self.assertEqual(orig.read_bytes(), orig_content, "Restored content must match original")
        self.assertEqual(sha256_bytes(orig.read_bytes()), pre_hash)
        self.assertTrue(target.exists(), "Tampered .locked file must be preserved for forensic analysis")
        self.assertTrue(journal_file.exists(), "Recovery journal must be preserved when tampering is detected")

    def test_scenario_10_hash_mismatched_orphan_when_original_intact(self):
        """Scenario 10: Original is intact, but orphaned .locked file has wrong/mismatched hash.
        Expected: Preserve intact original, REFUSE to delete mismatched orphan, report error.
        """
        import json
        orig = self.run_dir / "doc10.txt"
        orig_content = b"Legal Compliance Policy Original"
        orig.write_bytes(orig_content)
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        # Orphaned file on disk with alien/mismatched content
        orphan_locked = self.run_dir / "doc10.txt.locked"
        orphan_locked.write_bytes(b"ALIEN_NON_SIMULATION_DATA")

        journal = [
            {
                "original_path": str(orig),
                "staged_path": str(self.run_dir / "doc10.txt.stage.tmp"),
                "target_path": str(orphan_locked),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text(json.dumps(journal, indent=2))

        error_count = sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists(), "Original must remain intact")
        self.assertEqual(orig.read_bytes(), orig_content)
        self.assertTrue(orphan_locked.exists(), "Mismatched orphan must NOT be deleted")
        self.assertGreaterEqual(error_count, 1, "Must report error for mismatched orphan")

    def test_scenario_11_path_traversal_in_journal_record(self):
        """Scenario 11: Journal record attempts path traversal outside run directory.
        Expected: SystemExit(1) manifest abort; zero file operations performed.
        """
        import json
        escaped_path = self.test_dir.parent / "system_critical_file.txt"
        journal = [
            {
                "original_path": str(escaped_path),
                "staged_path": str(self.run_dir / "doc11.txt.stage.tmp"),
                "target_path": str(self.run_dir / "doc11.txt.locked"),
                "pre_modification_sha256": "fakehash",
                "post_modification_sha256": "fakehash",
                "status": "COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text(json.dumps(journal, indent=2))

        with self.assertRaises(SystemExit) as cm:
            sim.restore_mode(str(journal_file))
        self.assertEqual(cm.exception.code, 1)

    def test_scenario_12_restore_destination_collision_before_rename(self):
        """Scenario 12: Destination file appears right before rename (atomic collision).
        Expected: Collision detected; existing destination preserved; .restore.tmp cleaned up;
        error reported.
        """
        import json
        orig = self.run_dir / "doc12.txt"
        orig_content = b"Executive Board Minutes Confidential"
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc12.txt.locked"
        target.write_bytes(enc_content)

        journal = [
            {
                "original_path": str(orig),
                "target_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text(json.dumps(journal, indent=2))

        # To simulate race condition where original is recreated right after decryption staging begins,
        # we hook Path.write_bytes or pre-create orig right when .restore.tmp is written.
        # Here we mock Path.rename on the temporary restore file to raise FileExistsError.
        real_rename = Path.rename

        def mock_rename(*args, **kwargs):
            target = args[1] if len(args) > 1 else args[0]
            if str(target).endswith("doc12.txt"):
                # Pre-create the colliding destination
                Path(target).write_bytes(b"COLLIDING_FILE_WRITTEN_CONCURRENTLY")
                raise FileExistsError(f"Destination {target} already exists.")
            return real_rename(*args, **kwargs)

        from unittest.mock import patch
        with patch.object(Path, "rename", side_effect=mock_rename):
            error_count = sim.restore_mode(str(journal_file))

        self.assertGreaterEqual(error_count, 1, "Must report error on collision")
        self.assertEqual(orig.read_bytes(), b"COLLIDING_FILE_WRITTEN_CONCURRENTLY")
        tmp_restore = self.run_dir / "doc12.txt.restore.tmp"
        self.assertFalse(tmp_restore.exists(), "Temporary restore file must be cleaned up on collision")

    def test_scenario_13_artifact_cleanup_failure_reflected_in_error_count(self):
        """Scenario 13: Simulation artifact cleanup fails due to locked handle.
        Expected: safe_unlink_file returning False increments error_count;
        un-deleted artifact remains preserved; failure is reported in restoration summary.
        """
        import json
        orig = self.run_dir / "doc13.txt"
        orig_content = b"Encrypted Database Password Vault"
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc13.txt.locked"
        target.write_bytes(enc_content)

        # Pre-create the simulation artifacts that cleanup will target
        sim_log = self.run_dir / "simulation_log.txt"
        sim_log.write_text("Simulated execution log")
        ransom_note = self.run_dir / sim.RANSOM_NOTE_FILENAME
        ransom_note.write_text("Simulated ransom note")

        journal = [
            {
                "original_path": str(orig),
                "target_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text(json.dumps(journal, indent=2))

        # Mock safe_unlink_file so that attempting to delete simulation_log.txt fails (returns False)
        real_safe_unlink = sim.safe_unlink_file

        def mock_safe_unlink(filepath, label="file"):
            if filepath.name == "simulation_log.txt":
                return False  # Simulate locked file or access denied
            return real_safe_unlink(filepath, label)

        from unittest.mock import patch
        with patch("custom_behavior_sim.safe_unlink_file", side_effect=mock_safe_unlink):
            error_count = sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists(), "Original file must be restored")
        self.assertEqual(orig.read_bytes(), orig_content)
        self.assertGreaterEqual(error_count, 1, "Failed artifact cleanup must be reflected in error_count")
        self.assertTrue(sim_log.exists(), "Un-deleted artifact must remain on disk")
        self.assertTrue(journal_file.exists(), "Recovery journal must be preserved when artifact cleanup halts")

    def test_scenario_14_run_dir_rmdir_failure_reflected_in_final_summary(self):
        """Scenario 14: Run directory rmdir fails due to directory lock / sharing violation.
        Expected: Recovery remains successful for original file; run directory remains preserved;
        error_count increments; final summary reports that increased count.
        """
        import json
        orig = self.run_dir / "doc14.txt"
        orig_content = b"Proprietary Source Code Core Engine"
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc14.txt.locked"
        target.write_bytes(enc_content)

        journal = [
            {
                "original_path": str(orig),
                "target_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text(json.dumps(journal, indent=2))

        # Mock Path.iterdir so run_dir appears empty for rmdir attempt, and Path.rmdir to raise OSError
        def mock_iterdir(*args, **kwargs):
            return iter([])

        from unittest.mock import patch
        with self.assertLogs(level="INFO") as captured:
            with patch.object(Path, "iterdir", side_effect=mock_iterdir), \
                 patch.object(
                     Path,
                     "rmdir",
                     side_effect=OSError("Sharing violation / directory locked")
                 ):
                error_count = sim.restore_mode(str(journal_file))

        summary_lines = [
            message for message in captured.output
            if "[RESTORE] Complete — Restored:" in message
        ]
        self.assertTrue(summary_lines, "Final restoration summary was not logged")
        self.assertIn("Errors: 1", summary_lines[-1])
        self.assertGreaterEqual(error_count, 1)

        self.assertTrue(orig.exists(), "Original file must be restored")
        self.assertEqual(orig.read_bytes(), orig_content, "Restored content must match")
        self.assertTrue(self.run_dir.exists(), "Run directory must remain present on disk")

    def test_scenario_15_directory_enumeration_failure(self):
        """Scenario 15: Directory enumeration failure during final directory cleanup stage.
        Path.iterdir() raises PermissionError / OSError.
        Verify:
        1. Original file is restored and SHA-256 matches expected original hash.
        2. restore_mode() does not propagate the PermissionError.
        3. error_count is at least 1.
        4. Final summary is logged and reports the increased error count ("Errors: 1").
        5. Run directory is not removed.
        """
        import json
        orig = self.run_dir / "doc15.txt"
        orig_content = b"Confidential Database Records and Keys"
        pre_hash = sha256_bytes(orig_content)

        enc_content = bytes(b ^ XOR_KEY for b in orig_content)
        enc_hash = sha256_bytes(enc_content)

        target = self.run_dir / "doc15.txt.locked"
        target.write_bytes(enc_content)

        journal = [
            {
                "original_path": str(orig),
                "target_path": str(target),
                "pre_modification_sha256": pre_hash,
                "post_modification_sha256": enc_hash,
                "status": "COMMITTED",
            }
        ]
        journal_file = self.run_dir / "recovery_journal.json"
        journal_file.write_text(json.dumps(journal, indent=2))

        from unittest.mock import patch
        with self.assertLogs(level="INFO") as captured:
            with patch.object(
                Path,
                "iterdir",
                side_effect=PermissionError("Access is denied / directory locked by antivirus")
            ):
                error_count = sim.restore_mode(str(journal_file))

        self.assertTrue(orig.exists(), "Original file must be restored")
        self.assertEqual(orig.read_bytes(), orig_content, "Restored content must match original bytes")
        self.assertEqual(sha256_bytes(orig.read_bytes()), pre_hash, "Restored SHA-256 must match pre-simulation hash")
        self.assertTrue(self.run_dir.exists(), "Run directory must not be removed on enumeration failure")
        self.assertGreaterEqual(error_count, 1, "Directory enumeration failure must increase error_count")

        summary_lines = [
            message for message in captured.output
            if "[RESTORE] Complete — Restored:" in message
        ]
        self.assertTrue(summary_lines, "Final restoration summary was not logged")
        self.assertIn("Errors: 1", summary_lines[-1], "Final summary must report the enumeration error")


if __name__ == "__main__":
    unittest.main()


