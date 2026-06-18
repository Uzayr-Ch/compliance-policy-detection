"""
Severity classification matrix with context-aware modifiers and stateful
temporal escalation.

The matrix applies three layers of logic:

1.  **Base severity** from the parsed policy rule (LOW / MEDIUM / HIGH / CRITICAL).
2.  **Context modifiers** that inspect the detection description for proximity
    signals (e.g. nearby forklifts, personnel near panels).
3.  **Stateful temporal escalation** — if the *same* behavior class was already
    detected within a configurable recurrence window (default 300 s), the
    severity is bumped by one tier (capped at CRITICAL).
"""
from __future__ import annotations

from datetime import datetime
from src.models import DetectionRecord, BehaviorRule, SEVERITY_INDEX, SEVERITIES


# Recurrence window in seconds: same-class violations within this window
# trigger automatic one-tier escalation.
RECURRENCE_WINDOW_SECONDS = 300


def _escalate(severity: str) -> str:
    """Return the next-higher severity tier, capped at CRITICAL."""
    idx = SEVERITY_INDEX.get(severity, 1)
    return SEVERITIES[min(idx + 1, len(SEVERITIES) - 1)]


def _apply_context_modifiers(
    severity: str, rule: BehaviorRule, description: str
) -> str:
    """
    Apply context-aware modifiers based on the detection description text.

    Returns the (possibly upgraded) severity string.
    """
    text = description.lower()

    if rule.unsafe_behavior == "Opened Panel Cover":
        # An open panel is LOW by default but escalates to HIGH if workers are nearby.
        # Negation phrases like "no personnel nearby" must NOT trigger escalation.
        negation_patterns = ("no personnel", "no worker", "no person", "nobody", "unoccupied", "empty area")
        has_negation = any(neg in text for neg in negation_patterns)

        proximity_signals = ("personnel nearby", "worker", "proximity", "person near", "standing near")
        has_proximity = any(kw in text for kw in proximity_signals)

        if has_proximity and not has_negation:
            severity = "HIGH"
        else:
            severity = "LOW"

    elif rule.unsafe_behavior == "Safe Walkway Violation":
        # Walkway violation escalates to HIGH if vehicles / forklifts present
        vehicle_signals = ("forklift", "machinery", "transit", "vehicle", "truck")
        if any(kw in text for kw in vehicle_signals):
            severity = "HIGH"
        else:
            severity = "MEDIUM"

    # CRITICAL SAFETY NOTICE in the policy always overrides to CRITICAL
    if rule.hazard_signal == "CRITICAL SAFETY NOTICE":
        severity = "CRITICAL"

    return severity


def _check_temporal_recurrence(
    behavior_class: str,
    current_ts: str | None,
    recent_events: list[dict],
) -> bool:
    """
    Return True if a same-class event occurred within the recurrence window.

    Parses ISO-8601 timestamps; returns False on any parse failure so that
    the system degrades gracefully.
    """
    if not recent_events or not current_ts:
        return False

    try:
        now = datetime.fromisoformat(current_ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False

    for evt in recent_events:
        if evt.get("behavior_class") != behavior_class:
            continue
        try:
            evt_ts = datetime.fromisoformat(
                evt["timestamp"].replace("Z", "+00:00")
            )
        except (ValueError, KeyError):
            continue
        delta = abs((now - evt_ts).total_seconds())
        if delta <= RECURRENCE_WINDOW_SECONDS:
            return True

    return False


def categorize(
    detection: DetectionRecord,
    rules: list[BehaviorRule],
    recent_events: list[dict] | None = None,
    current_timestamp: str | None = None,
) -> str:
    """
    Determine the final severity for a detection record.

    Parameters
    ----------
    detection : DetectionRecord
        The raw detection from the vision engine.
    rules : list[BehaviorRule]
        All policy rules extracted from the compliance PDF.
    recent_events : list[dict] | None
        Previously recorded compliance events (dicts with at least
        ``behavior_class`` and ``timestamp`` keys).
    current_timestamp : str | None
        ISO-8601 timestamp of the *current* event for temporal comparison.

    Returns
    -------
    str
        One of ``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``.
    """
    rule = next(
        (r for r in rules if r.unsafe_behavior == detection.behavior_class),
        None,
    )
    if rule is None:
        return "MEDIUM"

    # Layer 1: base severity from the policy rule
    severity = rule.default_severity

    # Layer 2: context-aware modifiers
    severity = _apply_context_modifiers(severity, rule, detection.observed_behavior)

    # Layer 3: stateful temporal escalation
    if recent_events and _check_temporal_recurrence(
        detection.behavior_class, current_timestamp, recent_events
    ):
        severity = _escalate(severity)

    return severity
