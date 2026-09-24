"""Abstract Base Detector interface for log security analysis."""
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Union
import yaml

from ..models import Finding, LogEntry

logger = logging.getLogger(__name__)


class RuleValidationError(Exception):
    """Raised when a detection rule configuration fails validation."""
    pass


class BaseDetector(ABC):
    """Abstract base class for pluggable detection modules."""

    def __init__(
        self,
        config_path: Optional[Union[str, Path]] = None,
        enabled: bool = True,
        strict: bool = True,
    ):
        self.enabled = enabled
        self.strict = strict
        self.config_path = Path(config_path) if config_path else None
        self.config = {}
        if self.config_path and self.config_path.exists():
            self.load_config(self.config_path)

    def load_config(self, config_path: Path) -> None:
        """Load YAML configuration for the detector."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
        except Exception as e:
            msg = f"Failed to parse YAML configuration at {config_path}: {e}"
            logger.error(msg)
            if self.strict:
                raise RuleValidationError(msg) from e
            self.config = {}

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
