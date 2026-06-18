from __future__ import annotations


def route_for_severity(severity: str) -> str:
    if severity in {"HIGH", "CRITICAL"}:
        return "Real-time alert triggered + DB log"
    return "Logged to DB"


def alert_required(severity: str) -> bool:
    return severity in {"HIGH", "CRITICAL"}
