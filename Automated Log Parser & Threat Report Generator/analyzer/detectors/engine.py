"""Detection Engine coordinating all data-driven security detectors."""
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

from ..models import Finding, LogEntry
from .base import BaseDetector
from .bruteforce import BruteForceDetector
from .scanner_ua import ScannerUADetector
from .sqli import SQLiDetector
from .status_burst import StatusBurstDetector
from .traversal import TraversalDetector


class DetectionEngine:
    """Central engine managing detector execution and findings aggregation."""

    def __init__(self, rules_dir: Optional[Union[str, Path]] = None):
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).resolve().parent.parent.parent / "rules"
        self.detectors: List[BaseDetector] = []
        self._initialize_default_detectors()

    def _initialize_default_detectors(self) -> None:
        """Initialize all standard detectors with their respective YAML configurations."""
        self.detectors = [
            SQLiDetector(config_path=self.rules_dir / "sqli.yaml"),
            TraversalDetector(config_path=self.rules_dir / "traversal.yaml"),
            ScannerUADetector(config_path=self.rules_dir / "scanner_ua.yaml"),
            BruteForceDetector(config_path=self.rules_dir / "bruteforce.yaml"),
            StatusBurstDetector(config_path=self.rules_dir / "status_burst.yaml"),
        ]

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a custom detector instance."""
        self.detectors.append(detector)

    def reset(self) -> None:
        """Reset state across all stateful detectors."""
        for detector in self.detectors:
            detector.reset()

    def process_entry(self, entry: LogEntry) -> List[Finding]:
        """Run all registered detectors against a single log entry."""
        entry_findings: List[Finding] = []
        for detector in self.detectors:
            if detector.enabled:
                findings = detector.process(entry)
                if findings:
                    entry_findings.extend(findings)
        return entry_findings

    def process_stream(self, entries: Iterable[LogEntry]) -> List[Finding]:
        """Stream log entries through the engine and collect all security findings."""
        all_findings: List[Finding] = []
        for entry in entries:
            findings = self.process_entry(entry)
            if findings:
                all_findings.extend(findings)
        return all_findings
