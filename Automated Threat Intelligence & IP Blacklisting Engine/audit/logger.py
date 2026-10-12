"""
audit/logger.py — Run history and decision audit logging
=========================================================
Writes comprehensive JSONL audit records for every pipeline execution.
Records:
  - Run metadata (timestamp, duration, run_id)
  - Policy decisions (action, score, attribution, reason)
  - Expirations (purged IPs, scores, reasons)
  - Enforcement changes (added, removed, skipped)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuditLogger:
    """Manages appending and reading execution records from run_history.jsonl."""

    def __init__(self, log_path: str | Path = "data/run_history.jsonl") -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_run(self, run_record: dict[str, Any]) -> None:
        """
        Append a single run record as a JSON line.

        Args:
            run_record: Dictionary containing run summary, decisions, and expirations.
        """
        try:
            line = json.dumps(run_record, default=str)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as exc:
            logger.error("Failed to write audit record to %s: %s", self.log_path, exc)
            raise

    def get_recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        """
        Read the most recent runs from the log file (newest first).

        Args:
            limit: Maximum number of recent runs to return.

        Returns:
            List of parsed run record dictionaries.
        """
        if not self.log_path.exists():
            return []

        records: list[dict[str, Any]] = []
        try:
            with self.log_path.open("r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        data = json.loads(stripped)
                        records.append(data)
                    except json.JSONDecodeError as exc:
                        logger.warning(
                            "Skipping corrupt JSON line %d in %s: %s",
                            line_num,
                            self.log_path,
                            exc,
                        )
        except Exception as exc:
            logger.error("Failed to read audit log %s: %s", self.log_path, exc)
            return []

        # Return newest first up to limit
        return list(reversed(records))[:limit]

    def get_total_runs(self) -> int:
        """Return total number of valid run records in the log."""
        if not self.log_path.exists():
            return 0

        count = 0
        try:
            with self.log_path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        count += 1
        except Exception as exc:
            logger.error("Failed to count runs in %s: %s", self.log_path, exc)
        return count
