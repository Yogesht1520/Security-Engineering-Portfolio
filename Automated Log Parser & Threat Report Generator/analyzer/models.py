"""Core data models for log analysis, findings, and metrics."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass(frozen=True)
class LogEntry:
    """Structured representation of a parsed web server access log line."""
    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    referrer: str
    user_agent: str
    raw: str
    line_number: int


@dataclass
class Finding:
    """Represents an identified security threat or anomaly."""
    rule_id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    attack_type: str  # e.g., SQL Injection, Path Traversal, Brute Force
    ip: str
    timestamp: datetime
    evidence: str
    description: str
    location: str = "URI Path"  # e.g., URI Path, User-Agent, Status Sequence
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_city: Optional[str] = None
    rdns_hostname: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParserStats:
    """Statistical tracking for log ingestion and parsing throughput."""
    total_lines: int = 0
    parsed_lines: int = 0
    malformed_lines: int = 0
    format_detected: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return max((self.end_time - self.start_time).total_seconds(), 0.000001)
        return 0.0

    @property
    def lines_per_second(self) -> float:
        if self.duration_seconds > 0:
            return self.total_lines / self.duration_seconds
        return 0.0
