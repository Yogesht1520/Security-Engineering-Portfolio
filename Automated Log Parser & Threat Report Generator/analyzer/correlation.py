"""Incident correlation engine aggregating security findings into multi-stage threat campaigns."""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

from .models import Finding

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


@dataclass
class Incident:
    """Represents a correlated security incident aggregating multiple findings for an adversary."""
    incident_id: str
    ip: str
    title: str
    severity: str
    findings: List[Finding]
    attack_vectors: List[str]
    mitre_tactics: List[str]
    start_time: datetime
    end_time: datetime
    confidence_score: float
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_city: Optional[str] = None
    rdns_hostname: Optional[str] = None
    asn_org: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        return max((self.end_time - self.start_time).total_seconds(), 0.0)

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class CorrelationEngine:
    """Correlates atomic findings into multi-stage attack incidents using temporal and vector heuristics."""

    def __init__(self, window_seconds: int = 1800):
        """
        Args:
            window_seconds: Maximum time gap (in seconds) between findings from the same IP
                           to be grouped into the same incident (default: 30 minutes).
        """
        self.window_seconds = window_seconds

    def correlate(self, findings: List[Finding]) -> List[Incident]:
        """Correlate a list of findings into structured Security Incidents."""
        if not findings:
            return []

        # Sort findings by IP and timestamp
        sorted_findings = sorted(findings, key=lambda f: (f.ip or "", f.timestamp))

        # Group findings by IP into temporal clusters
        ip_clusters: Dict[str, List[List[Finding]]] = {}
        for f in sorted_findings:
            if not f.ip:
                continue
            clusters = ip_clusters.setdefault(f.ip, [])
            if not clusters:
                clusters.append([f])
            else:
                last_cluster = clusters[-1]
                last_time = last_cluster[-1].timestamp
                if (f.timestamp - last_time).total_seconds() <= self.window_seconds:
                    last_cluster.append(f)
                else:
                    clusters.append([f])

        incidents: List[Incident] = []
        inc_counter = 1

        for ip, clusters in ip_clusters.items():
            for cluster in clusters:
                inc = self._create_incident_from_cluster(ip, cluster, inc_counter)
                incidents.append(inc)
                inc_counter += 1

        # Sort incidents: highest severity first, then by finding count descending
        incidents.sort(
            key=lambda inc: (SEVERITY_ORDER.get(inc.severity.upper(), 0), inc.finding_count),
            reverse=True,
        )

        return incidents

    def _create_incident_from_cluster(self, ip: str, cluster: List[Finding], index: int) -> Incident:
        start_time = min(f.timestamp for f in cluster)
        end_time = max(f.timestamp for f in cluster)
        vectors = sorted(list({f.attack_type for f in cluster}))

        # Extract MITRE tactics
        tactics: Set[str] = set()
        for f in cluster:
            mid = f.metadata.get("mitre_attack_id")
            if mid:
                tactics.add(mid)

        first_finding = cluster[0]
        max_base_sev = max(cluster, key=lambda f: SEVERITY_ORDER.get(f.severity.upper(), 0)).severity.upper()

        # Severity elevation heuristics:
        # If multiple distinct attack vectors occur from same IP, elevate severity to CRITICAL or HIGH
        if len(vectors) >= 3 or ("SQL Injection" in vectors and "Path Traversal" in vectors):
            severity = "CRITICAL"
            title = f"Multi-Stage Cyber Attack Campaign ({' + '.join(vectors[:2])})"
        elif len(vectors) >= 2:
            severity = "CRITICAL" if max_base_sev == "CRITICAL" else "HIGH"
            title = f"Coordinated Multi-Vector Threat ({' + '.join(vectors)})"
        elif len(cluster) >= 10:
            severity = "HIGH" if max_base_sev in ("MEDIUM", "LOW") else max_base_sev
            title = f"High-Volume {vectors[0]} Activity Burst"
        else:
            severity = max_base_sev
            title = f"{vectors[0]} Incident"

        # Calculate confidence score (0.50 to 0.99)
        base_confidence = 0.70
        if len(vectors) >= 3:
            base_confidence += 0.20
        elif len(vectors) == 2:
            base_confidence += 0.15

        if len(cluster) >= 5:
            base_confidence += 0.09
        elif len(cluster) >= 3:
            base_confidence += 0.05

        confidence = min(round(base_confidence, 2), 0.99)

        return Incident(
            incident_id=f"INC-{index:03d}",
            ip=ip,
            title=title,
            severity=severity,
            findings=cluster,
            attack_vectors=vectors,
            mitre_tactics=sorted(list(tactics)),
            start_time=start_time,
            end_time=end_time,
            confidence_score=confidence,
            geo_country=first_finding.geo_country,
            geo_country_code=first_finding.geo_country_code,
            geo_city=first_finding.geo_city,
            rdns_hostname=first_finding.rdns_hostname,
            asn_org=first_finding.metadata.get("asn_org"),
        )
