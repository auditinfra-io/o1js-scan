"""Minimal, dependency-free finding types used by the o1js scanner.

Kept intentionally small: a severity enum and a `Vulnerability` record with a
`to_dict()` for JSON output. No third-party dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple


class Severity(Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Ordering, most severe first, for threshold comparisons (e.g. the CLI exit
# gate). Higher rank == more severe.
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def severity_rank(value: str) -> int:
    """Rank a severity string; unknown values rank as the least severe."""
    v = value.lower()
    return _SEVERITY_ORDER.index(v) if v in _SEVERITY_ORDER else 0


def meets_threshold(value: str, threshold: str) -> bool:
    """True if a finding of severity ``value`` is at least as severe as
    ``threshold``. A ``threshold`` of ``"none"`` never matches (gate disabled)."""
    if threshold.lower() == "none":
        return False
    return severity_rank(value) >= severity_rank(threshold)


@dataclass
class Vulnerability:
    """A detected soundness issue with evidence and provenance."""

    pattern_name: str
    severity: Severity
    function: str = ""
    location: Optional[Tuple[int, int]] = None  # (line, column)
    description: str = ""
    evidence: Optional[Dict] = None
    rule_id: str = ""
    title: str = ""
    origin_tier: str = "o1js"

    def __post_init__(self) -> None:
        if not self.rule_id:
            self.rule_id = self.pattern_name

    def to_dict(self) -> Dict:
        """Convert to a plain dict for JSON reporting."""
        sev = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        return {
            "rule_id": self.rule_id or self.pattern_name,
            "title": self.title or self.pattern_name,
            "pattern_name": self.pattern_name,
            "severity": sev.lower(),
            "function": self.function,
            "location": list(self.location) if self.location else None,
            "description": self.description,
            "evidence": self.evidence,
            "origin_tier": self.origin_tier,
        }
