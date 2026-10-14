"""
enforcement/rollback.py — Last-Known-Good (LKG) snapshots and atomic rollback
==============================================================================
Restores firewall state to the last known-good snapshot rather than simply
wiping all rules in an emergency.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from enforcement.base_adapter import BaseEnforcer

logger = logging.getLogger(__name__)


class SnapshotManager:
    """Manages Last-Known-Good (LKG) blocklist snapshots on disk."""

    def __init__(self, snapshot_dir: str | Path = "data/snapshots") -> None:
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def save_snapshot(
        self,
        enforcer_name: str,
        active_ips: list[str],
        run_id: str,
    ) -> Path:
        """Save a new LKG snapshot file."""
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")
        filename = f"lkg_{timestamp_str}_{run_id[:8]}.json"
        target_path = self.snapshot_dir / filename

        payload = {
            "snapshot_id": f"{timestamp_str}_{run_id[:8]}",
            "created_at": now.isoformat(),
            "enforcer_name": enforcer_name,
            "count": len(active_ips),
            "ips": sorted(list(set(active_ips))),
        }

        target_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Saved Last-Known-Good snapshot: %s (%d IPs)", target_path, len(active_ips))
        return target_path

    def get_latest_snapshot(self) -> dict[str, Any] | None:
        """Find and parse the most recent snapshot file."""
        snapshots = sorted(self.snapshot_dir.glob("lkg_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not snapshots:
            return None

        latest_path = snapshots[0]
        try:
            return json.loads(latest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to read snapshot file %s: %s", latest_path, exc)
            return None

    def rollback(
        self,
        adapter: BaseEnforcer,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """
        Rollback adapter's current set to match the latest LKG snapshot.

        Computes:
          to_add    = snapshot_ips - current_ips
          to_remove = current_ips - snapshot_ips
        """
        snapshot = self.get_latest_snapshot()
        if snapshot is None:
            raise FileNotFoundError("No Last-Known-Good snapshot found in " + str(self.snapshot_dir))

        target_ips = set(snapshot.get("ips", []))
        current_ips = adapter.current_set() if not dry_run else set()

        to_add = list(target_ips - current_ips)
        to_remove = list(current_ips - target_ips)

        added = 0
        removed = 0

        if not dry_run:
            if to_add:
                added = adapter.add(to_add)
            if to_remove:
                removed = adapter.remove(to_remove)
        else:
            added = len(to_add)
            removed = len(to_remove)

        logger.info(
            "Rollback completed (%s): Restored %s (%d total; +%d added, -%d removed)",
            "DRY-RUN" if dry_run else "APPLIED",
            snapshot["snapshot_id"],
            len(target_ips),
            added,
            removed,
        )

        return {
            "snapshot_id": snapshot["snapshot_id"],
            "created_at": snapshot["created_at"],
            "total_target": len(target_ips),
            "added": added,
            "removed": removed,
            "dry_run": dry_run,
        }
