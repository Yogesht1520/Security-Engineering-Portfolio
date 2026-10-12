"""
storage/db.py — SQLite database interface for threat intelligence indicators
=============================================================================
Provides persistent storage, deduplication lookup, TTL tracking, and enforcement state.
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
    return d


class ThreatIntelDB:
    """SQLite CRUD interface for scored IPs and TTL tracking."""

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
        """Run schema.sql DDL — idempotent (CREATE TABLE/INDEX IF NOT EXISTS)."""
        schema_path = Path(__file__).parent / "schema.sql"
        sql = schema_path.read_text(encoding="utf-8")
        with self.conn:
            self.conn.executescript(sql)

    def upsert(self, scored_ip: ScoredIP) -> Literal["inserted", "updated"]:
        """
        INSERT new IP, or UPDATE existing:
          - always update: combined_score, sources, category, last_updated, expires_at
          - NEVER overwrite: first_seen, enforced
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        first_seen_iso = _to_iso(scored_ip.first_seen)
        expires_at_iso = _to_iso(scored_ip.expires_at)
        sources_json = json.dumps(scored_ip.sources)

        cursor = self.conn.cursor()
        cursor.execute("SELECT first_seen, enforced FROM scored_ips WHERE ip = ?", (scored_ip.ip,))
        row = cursor.fetchone()

        with self.conn:
            if row is None:
                self.conn.execute(
                    """
                    INSERT INTO scored_ips (
                        ip, combined_score, sources, category,
                        first_seen, last_updated, expires_at, enforced
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        scored_ip.ip,
                        scored_ip.combined_score,
                        sources_json,
                        scored_ip.category,
                        first_seen_iso,
                        now_iso,
                        expires_at_iso,
                    ),
                )
                return "inserted"
            else:
                self.conn.execute(
                    """
                    UPDATE scored_ips SET
                        combined_score = ?,
                        sources = ?,
                        category = ?,
                        last_updated = ?,
                        expires_at = ?
                    WHERE ip = ?
                    """,
                    (
                        scored_ip.combined_score,
                        sources_json,
                        scored_ip.category,
                        now_iso,
                        expires_at_iso,
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
