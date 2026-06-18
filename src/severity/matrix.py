from __future__ import annotations

from src.models import DetectionRecord, BehaviorRule


def categorize(detection: DetectionRecord, rules: list[BehaviorRule]) -> str:
    rule = next(
        (item for item in rules if item.unsafe_behavior == detection.behavior_class),
        None,
    )
    if rule is None:
        return "MEDIUM"

    severity = rule.default_severity
    text = detection.observed_behavior.lower()

    if rule.hazard_signal == "CRITICAL SAFETY NOTICE":
        return "CRITICAL"
    if rule.domain == "Electrical Safety" and "no personnel nearby" in text:
        return "LOW"
    if "personnel nearby" in text or "near forklift" in text or "active travel" in text:
        return "HIGH"
    return severity
