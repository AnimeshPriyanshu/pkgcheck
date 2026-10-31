"""Shared data models for pkgcheck."""

from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    EXPECTED = "Expected"
    SUSPICIOUS = "Suspicious"


@dataclass
class Finding:
    file: str
    status: Status
    reason: str
    snippet: str | None = None
    line: int | None = None
    explanation: str | None = None