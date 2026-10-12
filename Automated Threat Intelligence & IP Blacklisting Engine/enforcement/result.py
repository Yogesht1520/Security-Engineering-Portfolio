"""
enforcement/result.py — Dataclass for enforcement operations summary
=====================================================================
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EnforcementResult:
    """Summary of changes applied by an enforcement run."""

    added: int = 0
    removed: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
