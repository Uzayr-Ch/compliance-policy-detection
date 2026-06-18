"""
Core domain models for the Factory Compliance & Alert Escalation System.

Every compliance event is cryptographically signed with SHA-256 to create
an immutable, tamper-evident audit trail that satisfies regulatory requirements.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class BehaviorRule:
    """A single policy-defined unsafe behavior extracted from the compliance PDF."""

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
    """Raw detection output from the vision engine or manifest loader."""

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
    """
    Immutable compliance event with SHA-256 cryptographic integrity signature.

    The signature is computed over the core identification and classification
    fields so that any post-hoc modification to the audit log is detectable.
    """

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
    signature: str
    source_video: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def calculate_hash(self) -> str:
        """Recompute the SHA-256 signature from the event's core fields."""
        return calculate_signature(
            self.event_id,
            self.timestamp,
            self.clip_id,
            self.zone,
            self.behavior_class,
            self.policy_rule_ref,
            self.severity,
            self.escalation_action,
        )

    def verify(self) -> bool:
        """Return True if the stored signature matches the recomputed hash."""
        return self.signature == self.calculate_hash()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def calculate_signature(
    event_id: str,
    timestamp: str,
    clip_id: str,
    zone: str,
    behavior_class: str,
    policy_rule_ref: str,
    severity: str,
    escalation_action: str,
) -> str:
    """
    Compute a SHA-256 hex digest over pipe-delimited core fields.

    Formula:
        SHA256(event_id | timestamp | clip_id | zone | behavior_class
               | policy_rule_ref | severity | escalation_action)
    """
    payload = (
        f"{event_id}|{timestamp}|{clip_id}|{zone}"
        f"|{behavior_class}|{policy_rule_ref}|{severity}|{escalation_action}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def utc_now_iso() -> str:
    """ISO-8601 UTC timestamp without microseconds, e.g. 2026-06-18T12:00:00Z."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def new_event_id() -> str:
    """Generate a unique event identifier (UUID4)."""
    return str(uuid4())
