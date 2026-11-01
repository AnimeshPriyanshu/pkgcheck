"""Shared data models for pkgcheck."""

from dataclasses import dataclass, field
from enum import Enum


class Status(Enum):
    EXPECTED = "Expected"
    SUSPICIOUS = "Suspicious"


class Severity(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class Evidence:
    """Structured evidence from a detection rule."""
    rule: str
    evidence_type: str
    file: str
    description: str
    weight: int


@dataclass
class Finding:
    file: str
    status: Status
    reason: str
    snippet: str | None = None
    line: int | None = None
    explanation: str | None = None
    severity: Severity = Severity.INFO
    evidence: list[Evidence] = field(default_factory=list)