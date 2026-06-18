from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class BehaviorRule:
    class_id: int
    domain: str
    unsafe_behavior: str
    safe_behavior: str
    observable_indicator: str
    policy_rule_ref: str
    hazard_signal: str
    default_severity: str
    source_excerpt: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DetectionRecord:
    clip_id: str
    timestamp_seconds: float
    behavior_class: str
    policy_rule_ref: str
    observed_behavior: str
    zone: str
    confidence: float
    source_video: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ComplianceEvent:
    event_id: str
    timestamp: str
    clip_id: str
    zone: str
    behavior_class: str
    policy_rule_ref: str
    event_description: str
    severity: str
    escalation_action: str
    confidence: float
    source_video: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_event_id() -> str:
    return str(uuid4())
