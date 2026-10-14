"""
storage/db.py — SQLite database interface for threat intelligence indicators
=============================================================================
Provides persistent storage, deduplication lookup, TTL tracking, extended lifecycle
management, and feed health telemetry.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from models import ScoredIP


def _to_iso(dt: datetime | str) -> str:
    """Format a datetime to standard ISO-8601 UTC string."""
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert an sqlite3.Row to a dict, deserializing JSON fields."""
    d = dict(row)
    if "sources" in d and isinstance(d["sources"], str):
        try:
            d["sources"] = json.loads(d["sources"])
        except (json.JSONDecodeError, TypeError):
            d["sources"] = []
    if "evidence_json" in d and isinstance(d["evidence_json"], str):
        try:
            d["evidence"] = json.loads(d["evidence_json"])
        except (json.JSONDecodeError, TypeError):
            d["evidence"] = []
    return d


class ThreatIntelDB:
    """SQLite CRUD interface for scored IPs, indicator lifecycles, and feed health."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    def __enter__(self) -> ThreatIntelDB:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        """Close SQLite connection."""
        if self.conn:
            self.conn.close()

    def init_schema(self) -> None:
        """Run schema.sql DDL and apply non-destructive schema migrations."""
        schema_path = Path(__file__).parent / "schema.sql"
        sql = schema_path.read_text(encoding="utf-8")
        with self.conn:
            self.conn.executescript(sql)

            # Migration: Ensure new lifecycle columns exist in existing scored_ips tables
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA table_info(scored_ips)")
            existing_cols = {col["name"] for col in cursor.fetchall()}

            migrations = [
                ("last_seen", "TEXT"),
                ("last_confirmed", "TEXT"),
                ("source_count", "INTEGER NOT NULL DEFAULT 1"),
                ("status", "TEXT NOT NULL DEFAULT 'blocked'"),
                ("reason", "TEXT NOT NULL DEFAULT ''"),
                ("evidence_json", "TEXT NOT NULL DEFAULT '[]'"),
            ]
            for col_name, col_def in migrations:
                if col_name not in existing_cols:
                    self.conn.execute(f"ALTER TABLE scored_ips ADD COLUMN {col_name} {col_def}")

            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON scored_ips(status)")

    def upsert(
        self,
        scored_ip: ScoredIP,
        status: str = "blocked",
        reason: str = "",
    ) -> Literal["inserted", "updated"]:
        """
        INSERT new IP, or UPDATE existing indicator lifecycle:
          - always update: combined_score, sources, category, last_updated, last_seen, expires_at,
                           source_count, status, reason, evidence_json
          - update last_confirmed if 2+ sources independently corroborate
          - NEVER overwrite: first_seen, enforced
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        first_seen_iso = _to_iso(scored_ip.first_seen)
        expires_at_iso = _to_iso(scored_ip.expires_at)
        sources_json = json.dumps(scored_ip.sources)
        evidence_json = json.dumps(scored_ip.evidence) if scored_ip.evidence else "[]"
        source_count = len(scored_ip.sources)

        cursor = self.conn.cursor()
        cursor.execute("SELECT first_seen, enforced, last_confirmed FROM scored_ips WHERE ip = ?", (scored_ip.ip,))
        row = cursor.fetchone()

        with self.conn:
            if row is None:
                # Fresh indicator: last_confirmed set if multi-source
                last_confirmed = now_iso if source_count >= 2 else first_seen_iso
                self.conn.execute(
                    """
                    INSERT INTO scored_ips (
                        ip, combined_score, sources, category,
                        first_seen, last_seen, last_confirmed, last_updated, expires_at,
                        source_count, status, reason, evidence_json, enforced
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        scored_ip.ip,
                        scored_ip.combined_score,
                        sources_json,
                        scored_ip.category,
                        first_seen_iso,
                        now_iso,
                        last_confirmed,
                        now_iso,
                        expires_at_iso,
                        source_count,
                        status,
                        reason,
                        evidence_json,
                    ),
                )
                return "inserted"
            else:
                # Existing indicator: only advance last_confirmed if multi-source corroborated
                existing_confirmed = row["last_confirmed"]
                last_confirmed = now_iso if source_count >= 2 else (existing_confirmed or now_iso)

                self.conn.execute(
                    """
                    UPDATE scored_ips SET
                        combined_score = ?,
                        sources = ?,
                        category = ?,
                        last_seen = ?,
                        last_confirmed = ?,
                        last_updated = ?,
                        expires_at = ?,
                        source_count = ?,
                        status = ?,
                        reason = ?,
                        evidence_json = ?
                    WHERE ip = ?
                    """,
                    (
                        scored_ip.combined_score,
                        sources_json,
                        scored_ip.category,
                        now_iso,
                        last_confirmed,
                        now_iso,
                        expires_at_iso,
                        source_count,
                        status,
                        reason,
                        evidence_json,
                        scored_ip.ip,
                    ),
                )
                return "updated"

    def get_by_ip(self, ip: str) -> dict[str, Any] | None:
        """Fetch one row by primary key IP; return dict or None if not found."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM scored_ips WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row is None:
            return None
        return _row_to_dict(row)

    def get_expired(self, now: datetime | str | None = None) -> list[dict[str, Any]]:
        """All rows where expires_at < now (UTC)."""
        if now is None:
            now_iso = datetime.now(timezone.utc).isoformat()
        else:
            now_iso = _to_iso(now)

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM scored_ips WHERE expires_at < ? ORDER BY expires_at ASC",
            (now_iso,),
        )
        return [_row_to_dict(row) for row in cursor.fetchall()]

    def get_active(self, now: datetime | str | None = None) -> list[dict[str, Any]]:
        """All non-expired rows (expires_at >= now)."""
        if now is None:
            now_iso = datetime.now(timezone.utc).isoformat()
        else:
            now_iso = _to_iso(now)

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM scored_ips WHERE expires_at >= ? ORDER BY combined_score DESC",
            (now_iso,),
        )
        return [_row_to_dict(row) for row in cursor.fetchall()]

    def get_all(self) -> list[dict[str, Any]]:
        """Return all rows in the scored_ips table."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM scored_ips ORDER BY combined_score DESC")
        return [_row_to_dict(row) for row in cursor.fetchall()]

    def delete(self, ip: str) -> None:
        """Hard delete an IP record."""
        with self.conn:
            self.conn.execute("DELETE FROM scored_ips WHERE ip = ?", (ip,))

    def set_enforced(self, ip: str, enforced: bool) -> None:
        """Toggle the enforced flag after enforcement add/remove."""
        with self.conn:
            self.conn.execute(
                "UPDATE scored_ips SET enforced = ? WHERE ip = ?",
                (1 if enforced else 0, ip),
            )

    def record_feed_health(
        self,
        feed_name: str,
        status: str,
        duration_ms: float,
        indicators_received: int,
        rejected_count: int = 0,
        error_message: str | None = None,
    ) -> None:
        """Record or update health telemetry for a specific threat feed."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO feed_health (
                    feed_name, status, last_sync_utc, duration_ms,
                    indicators_received, rejected_count, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(feed_name) DO UPDATE SET
                    status = excluded.status,
                    last_sync_utc = excluded.last_sync_utc,
                    duration_ms = excluded.duration_ms,
                    indicators_received = excluded.indicators_received,
                    rejected_count = excluded.rejected_count,
                    error_message = excluded.error_message
                """,
                (
                    feed_name,
                    status,
                    now_iso,
                    duration_ms,
                    indicators_received,
                    rejected_count,
                    error_message,
                ),
            )

    def get_feed_health(self) -> list[dict[str, Any]]:
        """Retrieve latest health status for all monitored intelligence feeds."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM feed_health ORDER BY feed_name ASC")
        return [dict(row) for row in cursor.fetchall()]
