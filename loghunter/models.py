"""Core data structures shared by parsers, detectors and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Event:
    """A single normalised security event extracted from a log line."""

    timestamp: datetime
    source: str  # "ssh" or "web"
    action: str  # ssh_failed | ssh_accepted | ssh_invalid_user | http_request
    ip: str
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    user_agent: str | None = None
    raw: str = ""


@dataclass
class Alert:
    """A detection produced by a rule."""

    rule: str
    severity: str
    ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    description: str
    mitre: str
    evidence: list[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "description": self.description,
            "mitre": self.mitre,
            "evidence": self.evidence,
        }
