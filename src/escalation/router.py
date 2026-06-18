"""
Alert escalation router.

Maps severity tiers to concrete dispatch actions that mirror real-world
EHS (Environment, Health & Safety) incident response protocols.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Dispatch action table
# ---------------------------------------------------------------------------

_ACTIONS: dict[str, str] = {
    "LOW": "Log to compliance database",
    "MEDIUM": "Log + email notification to shift supervisor",
    "HIGH": "Log + SMS alert to EHS coordinator + floor alarm activation",
    "CRITICAL": (
        "Log + emergency dispatch to safety response team "
        "+ production line halt + audible siren + strobe activation"
    ),
}


def route_for_severity(severity: str) -> str:
    """Return the escalation action string for the given severity tier."""
    return _ACTIONS.get(severity, _ACTIONS["MEDIUM"])


def alert_required(severity: str) -> bool:
    """Return True if the severity warrants a real-time visual/audible alert."""
    return severity in {"HIGH", "CRITICAL"}
