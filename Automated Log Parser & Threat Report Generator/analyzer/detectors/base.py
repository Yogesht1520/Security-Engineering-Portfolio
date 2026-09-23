"""Abstract Base Detector interface for log security analysis."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Union
import yaml

from ..models import Finding, LogEntry


class BaseDetector(ABC):
    """Abstract base class for pluggable detection modules."""

    def __init__(self, config_path: Optional[Union[str, Path]] = None, enabled: bool = True):
        self.enabled = enabled
        self.config_path = Path(config_path) if config_path else None
        self.config = {}
        if self.config_path and self.config_path.exists():
            self.load_config(self.config_path)

    def load_config(self, config_path: Path) -> None:
        """Load YAML configuration for the detector."""
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f) or {}

    @abstractmethod
    def process(self, entry: LogEntry) -> List[Finding]:
        """
        Process a single LogEntry and return a list of identified Findings.
        Returns an empty list if no threats are detected.
        """
        pass

    def reset(self) -> None:
        """Reset internal state (useful for stateful sliding-window detectors)."""
        pass
