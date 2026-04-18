from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RuleLocation:
    path: Path
    group_name: str
    rule_index: int


@dataclass
class AlertRule:
    name: str
    expr: str
    duration: str | None
    labels: dict[str, Any]
    annotations: dict[str, Any]
    location: RuleLocation
    raw: dict[str, Any] = field(repr=False)

    def identifier(self) -> str:
        return f"{self.location.path}:{self.location.group_name}:{self.name}"


@dataclass
class Finding:
    check_id: str
    severity: str
    message: str
    suggestion: str
    impact: str | None
    path: Path
    group_name: str
    alert_name: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def sort_key(self) -> tuple[str, str, str, str]:
        return (
            str(self.path),
            self.group_name,
            self.alert_name or "",
            self.check_id,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["path"] = str(self.path)
        return payload
