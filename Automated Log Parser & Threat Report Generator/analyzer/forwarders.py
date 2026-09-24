"""SIEM ingestion forwarders for Splunk HEC, Elasticsearch, and Webhooks."""
import json
import logging
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .correlation import Incident
from .models import Finding

logger = logging.getLogger(__name__)


class BaseForwarder(ABC):
    """Abstract interface for SIEM and alert streaming sinks."""

    @abstractmethod
    def forward(
        self,
        summary: Dict[str, Any],
        incidents: List[Incident],
        findings: List[Finding],
    ) -> bool:
        pass


class SplunkHECForwarder(BaseForwarder):
    """Forwards security incidents and findings directly to Splunk HTTP Event Collector (HEC)."""

    def __init__(
        self,
        hec_url: str,
        token: str,
        index: str = "main",
        source: str = "log_threat_analyzer",
        sourcetype: str = "soc:threat:detection",
        timeout: float = 10.0,
    ):
        self.hec_url = hec_url.rstrip("/")
        if not self.hec_url.endswith("/services/collector/event"):
            self.hec_url = f"{self.hec_url}/services/collector/event"
        self.token = token
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self.timeout = timeout

    def forward(
        self,
        summary: Dict[str, Any],
        incidents: List[Incident],
        findings: List[Finding],
    ) -> bool:
        if not self.hec_url or not self.token:
            return False

        events = []

        # 1. Forward summary event
        events.append({
            "event": {
                "event_type": "summary",
                "summary": summary,
            },
            "source": self.source,
            "sourcetype": f"{self.sourcetype}:summary",
            "index": self.index,
        })

        # 2. Forward correlated incidents
        for inc in incidents:
            events.append({
                "time": int(inc.start_time.timestamp()),
                "event": {
                    "event_type": "incident",
                    "incident_id": inc.incident_id,
                    "ip": inc.ip,
                    "title": inc.title,
                    "severity": inc.severity,
                    "attack_vectors": inc.attack_vectors,
                    "mitre_tactics": inc.mitre_tactics,
                    "finding_count": inc.finding_count,
                    "confidence_score": inc.confidence_score,
                    "geo_country": inc.geo_country,
                    "rdns_hostname": inc.rdns_hostname,
                },
                "source": self.source,
                "sourcetype": f"{self.sourcetype}:incident",
                "index": self.index,
            })

        # 3. Forward raw findings
        for f in findings:
            events.append({
                "time": int(f.timestamp.timestamp()),
                "event": {
                    "event_type": "finding",
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "attack_type": f.attack_type,
                    "ip": f.ip,
                    "location": f.location,
                    "description": f.description,
                    "evidence": f.evidence,
                    "metadata": f.metadata,
                },
                "source": self.source,
                "sourcetype": f"{self.sourcetype}:finding",
                "index": self.index,
            })

        # Send batch to Splunk HEC
        batch_payload = "\n".join(json.dumps(e) for e in events).encode("utf-8")
        req = urllib.request.Request(
            url=self.hec_url,
            data=batch_payload,
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status in (200, 201)
        except Exception as e:
            logger.error("Splunk HEC forwarding failed: %s", e)
            return False


class ElasticsearchForwarder(BaseForwarder):
    """Streams findings and incidents to Elasticsearch / OpenSearch via Bulk API."""

    def __init__(
        self,
        es_url: str,
        index_prefix: str = "threat-reports",
        auth_header: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.es_url = es_url.rstrip("/")
        self.index_prefix = index_prefix
        self.auth_header = auth_header
        self.timeout = timeout

    def forward(
        self,
        summary: Dict[str, Any],
        incidents: List[Incident],
        findings: List[Finding],
    ) -> bool:
        if not self.es_url:
            return False

        bulk_url = f"{self.es_url}/_bulk"
        lines = []

        # Bulk index action metadata
        idx = f"{self.index_prefix}-findings"
        for f in findings:
            action = {"index": {"_index": idx}}
            doc = {
                "@timestamp": f.timestamp.isoformat(),
                "rule_id": f.rule_id,
                "severity": f.severity,
                "attack_type": f.attack_type,
                "ip": f.ip,
                "location": f.location,
                "description": f.description,
                "evidence": f.evidence,
                "geo_country": f.geo_country,
                "geo_city": f.geo_city,
                "rdns_hostname": f.rdns_hostname,
                "metadata": f.metadata,
            }
            lines.append(json.dumps(action))
            lines.append(json.dumps(doc))

        if not lines:
            return True

        bulk_payload = ("\n".join(lines) + "\n").encode("utf-8")
        headers = {"Content-Type": "application/x-ndjson"}
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        req = urllib.request.Request(url=bulk_url, data=bulk_payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status in (200, 201)
        except Exception as e:
            logger.error("Elasticsearch bulk indexing failed: %s", e)
            return False


class WebhookForwarder(BaseForwarder):
    """Sends JSON alerts to Slack, Discord, Microsoft Teams, or custom webhook endpoints."""

    def __init__(self, webhook_url: str, timeout: float = 10.0):
        self.webhook_url = webhook_url
        self.timeout = timeout

    def forward(
        self,
        summary: Dict[str, Any],
        incidents: List[Incident],
        findings: List[Finding],
    ) -> bool:
        if not self.webhook_url:
            return False

        payload = {
            "title": "🚨 SOC Threat Analysis Alert",
            "summary": summary,
            "incident_count": len(incidents),
            "top_incidents": [
                {
                    "id": inc.incident_id,
                    "ip": inc.ip,
                    "title": inc.title,
                    "severity": inc.severity,
                    "confidence": f"{inc.confidence_score*100:.0f}%",
                    "vectors": inc.attack_vectors,
                }
                for inc in incidents[:5]
            ],
            "total_threat_events": len(findings),
        }

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url=self.webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status in (200, 201, 204)
        except Exception as e:
            logger.error("Webhook forwarding failed: %s", e)
            return False
