"""Persistent storage engine for streaming findings and incidents using SQLite."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Union

from .models import Finding


class SQLiteFindingStore:
    """Persistent on-disk store for security findings and correlated incidents."""

    def __init__(self, db_path: Union[str, Path] = ":memory:"):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=15.0)

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    evidence TEXT,
                    description TEXT,
                    location TEXT,
                    geo_country TEXT,
                    geo_country_code TEXT,
                    geo_city TEXT,
                    rdns_hostname TEXT,
                    metadata_json TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_ip ON findings(ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp)")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    confidence_score REAL,
                    finding_count INTEGER,
                    attack_vectors_json TEXT,
                    mitre_tactics_json TEXT
                )
                """
            )
            conn.commit()

    def add_finding(self, finding: Finding) -> None:
        """Insert a single finding into the persistent store."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO findings
                (rule_id, severity, attack_type, ip, timestamp, evidence, description, location,
                 geo_country, geo_country_code, geo_city, rdns_hostname, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.rule_id,
                    finding.severity,
                    finding.attack_type,
                    finding.ip,
                    finding.timestamp.isoformat(),
                    finding.evidence,
                    finding.description,
                    finding.location,
                    finding.geo_country,
                    finding.geo_country_code,
                    finding.geo_city,
                    finding.rdns_hostname,
                    json.dumps(finding.metadata),
                ),
            )
            conn.commit()

    def add_findings(self, findings: Iterable[Finding]) -> None:
        """Batch insert multiple findings efficiently."""
        records = []
        for f in findings:
            records.append((
                f.rule_id,
                f.severity,
                f.attack_type,
                f.ip,
                f.timestamp.isoformat(),
                f.evidence,
                f.description,
                f.location,
                f.geo_country,
                f.geo_country_code,
                f.geo_city,
                f.rdns_hostname,
                json.dumps(f.metadata),
            ))

        if not records:
            return

        with self._get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO findings
                (rule_id, severity, attack_type, ip, timestamp, evidence, description, location,
                 geo_country, geo_country_code, geo_city, rdns_hostname, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records,
            )
            conn.commit()

    def get_all_findings(self) -> List[Finding]:
        """Retrieve all stored findings."""
        findings: List[Finding] = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT rule_id, severity, attack_type, ip, timestamp, evidence, description,
                       location, geo_country, geo_country_code, geo_city, rdns_hostname, metadata_json
                FROM findings ORDER BY timestamp ASC
                """
            )
            for row in cursor.fetchall():
                ts = datetime.fromisoformat(row[4])
                meta = json.loads(row[12]) if row[12] else {}
                findings.append(
                    Finding(
                        rule_id=row[0],
                        severity=row[1],
                        attack_type=row[2],
                        ip=row[3],
                        timestamp=ts,
                        evidence=row[5],
                        description=row[6],
                        location=row[7],
                        geo_country=row[8],
                        geo_country_code=row[9],
                        geo_city=row[10],
                        rdns_hostname=row[11],
                        metadata=meta,
                    )
                )
        return findings

    def count(self) -> int:
        """Return total number of stored findings."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM findings")
            return cursor.fetchone()[0]
