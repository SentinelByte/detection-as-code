from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Tactic(str, Enum):
    """MITRE ATT&CK Enterprise tactics, keyed by their official ID."""

    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    COMMAND_AND_CONTROL = "TA0011"
    IMPACT = "TA0040"


@dataclass
class DetectionRule:
    """The vendor-neutral internal representation of a detection rule.

    Everything downstream (Kibana JSON, Sigma YAML, the deterministic linter,
    the AI critic) works off this one schema, so adding a new export target
    or a new check never requires touching the rule authoring format.
    """

    name: str
    platform: str
    query: str
    index_patterns: list[str]
    description: str
    severity: Severity
    risk_score: int
    tactics: list[Tactic] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    author: str = ""
    interval: str = "30m"
    lookback: str = "45m"
    enabled: bool = False
    rule_id: str | None = None

    def __post_init__(self) -> None:
        if not 0 < self.risk_score <= 100:
            raise ValueError(f"risk_score must be in (0, 100], got {self.risk_score}")
        if not self.name.strip():
            raise ValueError("name must not be empty")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetectionRule:
        try:
            severity = Severity(data["severity"])
        except ValueError as exc:
            allowed = ", ".join(s.value for s in Severity)
            raise ValueError(f"severity must be one of: {allowed}") from exc

        tactics = []
        for raw in data.get("tactics", []):
            try:
                tactics.append(Tactic[str(raw).upper()])
            except KeyError as exc:
                allowed = ", ".join(t.name for t in Tactic)
                raise ValueError(f"Unknown tactic {raw!r}, expected one of: {allowed}") from exc

        return cls(
            name=data["name"],
            platform=data["platform"],
            query=data["query"],
            index_patterns=list(data.get("index_patterns", [])),
            description=data.get("description", ""),
            severity=severity,
            risk_score=int(data["risk_score"]),
            tactics=tactics,
            techniques=list(data.get("techniques", [])),
            tags=list(data.get("tags", [])),
            false_positives=list(data.get("false_positives", [])),
            author=data.get("author", ""),
            interval=data.get("interval", "30m"),
            lookback=data.get("lookback", "45m"),
            enabled=bool(data.get("enabled", False)),
            rule_id=data.get("rule_id"),
        )
