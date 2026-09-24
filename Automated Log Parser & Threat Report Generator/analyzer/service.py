"""Lightweight HTTP API service mode for on-demand log analysis and SOC integration."""
import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional, Union
from urllib.parse import parse_qs, urlparse

# Hard cap on inbound request body size to prevent memory exhaustion from oversized payloads.
# Attacker-controlled input must be bounded before reading into process memory.
MAX_REQUEST_BODY = 10 * 1024 * 1024  # 10 MB

from .detectors import DetectionEngine
from .enrichment import IPEnricher
from .models import ParserStats
from .parser import LogParser
from .report import ReportBuilder

logger = logging.getLogger(__name__)


class ThreatAnalyzerAPIHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for threat analysis REST API endpoints."""

    engine: DetectionEngine
    enricher: IPEnricher
    parser: LogParser

    def _send_json(self, status_code: int, data: dict) -> None:
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        if path in ("/health", "/api/v1/health", ""):
            self._send_json(200, {
                "status": "healthy",
                "service": "Automated Log Threat Analyzer API",
                "version": "1.0.0",
                "detectors_loaded": len(self.engine.detectors),
                "endpoints": [
                    "GET  /api/v1/health",
                    "GET  /api/v1/rules",
                    "POST /api/v1/scan",
                    "POST /api/v1/enrich",
                ]
            })
            return

        if path == "/api/v1/rules":
            rules_summary = []
            for det in self.engine.detectors:
                rules_summary.append({
                    "detector": det.__class__.__name__,
                    "enabled": det.enabled,
                    "attack_type": det.config.get("attack_type", "Unknown"),
                    "rule_count": len(det.config.get("rules", [1])),
                })
            self._send_json(200, {"rules": rules_summary})
            return

        self._send_json(404, {"error": "Not Found", "path": self.path})

    def do_POST(self) -> None:
        parsed_url = urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_REQUEST_BODY:
            self._send_json(413, {
                "error": f"Request body too large ({content_length:,} bytes). Maximum allowed: {MAX_REQUEST_BODY:,} bytes."
            })
            return
        body_bytes = self.rfile.read(content_length)

        if path == "/api/v1/scan":
            raw_text = ""
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    payload = json.loads(body_bytes.decode("utf-8"))
                    raw_text = payload.get("log_data") or payload.get("logs") or ""
                except Exception as e:
                    self._send_json(400, {"error": f"Invalid JSON payload: {e}"})
                    return
            else:
                raw_text = body_bytes.decode("utf-8", errors="replace")

            if not raw_text.strip():
                self._send_json(400, {"error": "Empty log payload provided."})
                return

            # Analyze lines
            lines = raw_text.splitlines()
            parsed_entries = []
            malformed_count = 0

            for idx, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                entry = self.parser.parse_line(line, line_number=idx)
                if entry:
                    parsed_entries.append(entry)
                else:
                    malformed_count += 1

            self.engine.reset()
            raw_findings = self.engine.process_stream(parsed_entries)
            findings = self.enricher.enrich_findings(raw_findings)

            stats = ParserStats(
                total_lines=len(lines),
                parsed_lines=len(parsed_entries),
                malformed_lines=malformed_count,
            )

            builder = ReportBuilder(
                findings=findings,
                stats=stats,
                log_source="api_stream_payload",
                title="API Security Threat Scan",
            )

            report_json_str = builder.render_json()
            self._send_json(200, json.loads(report_json_str))
            return

        if path == "/api/v1/enrich":
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
                ip = payload.get("ip")
                if not ip:
                    self._send_json(400, {"error": "Missing 'ip' field in JSON request."})
                    return
                info = self.enricher.lookup(ip)
                self._send_json(200, {
                    "ip": info.ip,
                    "country_name": info.country_name,
                    "country_code": info.country_code,
                    "city": info.city,
                    "asn_org": info.asn_org,
                    "rdns_hostname": info.rdns_hostname,
                    "is_private": info.is_private,
                })
            except Exception as e:
                self._send_json(400, {"error": f"Invalid request: {e}"})
            return

        self._send_json(404, {"error": "Not Found", "path": self.path})

    def log_message(self, format: str, *args) -> None:
        """Suppress noisy default stdout HTTP logging."""
        logger.debug("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)


def create_service(
    rules_dir: Optional[Union[str, Path]] = None,
    geoip_path: Optional[Union[str, Path]] = None,
    enable_rdns: bool = True,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> HTTPServer:
    """Instantiate and configure HTTPServer with initialized detection engine and enricher.

    Note: Default bind address is 127.0.0.1 (localhost only). Pass host='0.0.0.0' explicitly
    to expose on all network interfaces. This service has no authentication — do not expose
    to untrusted networks without an authenticating reverse proxy in front of it.
    """
    engine = DetectionEngine(rules_dir=rules_dir)
    enricher = IPEnricher(geoip_db_path=geoip_path, enable_rdns=enable_rdns)
    parser = LogParser()

    class BoundHandler(ThreatAnalyzerAPIHandler):
        pass

    BoundHandler.engine = engine
    BoundHandler.enricher = enricher
    BoundHandler.parser = parser

    server = HTTPServer((host, port), BoundHandler)
    return server
