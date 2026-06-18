"""
End-to-end compliance pipeline orchestrator.

Connects the four core modules:
    Policy Parser → Detection Engine → Severity Matrix → Report Store

Each event receives a SHA-256 integrity signature before it is persisted
to the triple-format audit trail (SQLite + JSONL + CSV).
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in python path to handle direct script execution
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argparse

from src.detection.engine import detect_violations
from src.escalation.router import route_for_severity
from src.models import ComplianceEvent, new_event_id, utc_now_iso, calculate_signature
from src.policy.parser import load_rules, write_rules_json
from src.reports.store import append_event, init_db, load_events
from src.severity.matrix import categorize


def run_pipeline(
    demo: bool = False, data_dir: Path | None = None, persist: bool = True
) -> list[ComplianceEvent]:
    """
    Execute the full compliance pipeline.

    Parameters
    ----------
    demo : bool
        If True, generate deterministic synthetic detections for demonstration.
    data_dir : Path | None
        Directory containing input video clips or manifest.json.
    persist : bool
        If True, write events to the SQLite / JSONL / CSV audit trail.

    Returns
    -------
    list[ComplianceEvent]
        All generated compliance events.
    """
    rules = write_rules_json()
    detections = detect_violations(rules, data_dir=data_dir or Path("data"), demo=demo)

    if persist:
        init_db()
        history = load_events()
    else:
        history = []

    events: list[ComplianceEvent] = []

    for detection in detections:
        ts = utc_now_iso()

        severity = categorize(
            detection,
            rules,
            recent_events=history,
            current_timestamp=ts,
        )

        evt_id = new_event_id()
        action = route_for_severity(severity)

        sig = calculate_signature(
            event_id=evt_id,
            timestamp=ts,
            clip_id=detection.clip_id,
            zone=detection.zone,
            behavior_class=detection.behavior_class,
            policy_rule_ref=detection.policy_rule_ref,
            severity=severity,
            escalation_action=action,
        )

        event = ComplianceEvent(
            event_id=evt_id,
            timestamp=ts,
            clip_id=detection.clip_id,
            zone=detection.zone,
            behavior_class=detection.behavior_class,
            policy_rule_ref=detection.policy_rule_ref,
            event_description=detection.observed_behavior,
            severity=severity,
            escalation_action=action,
            confidence=detection.confidence,
            signature=sig,
            source_video=detection.source_video,
        )

        if persist:
            append_event(event)
            history.append(event.to_dict())

        events.append(event)

    return events


def main() -> None:
    ap = argparse.ArgumentParser(description="Factory compliance pipeline.")
    ap.add_argument("--demo", action="store_true", help="Use synthetic demo detections.")
    ap.add_argument("--data-dir", default="data", help="Path to input data directory.")
    args = ap.parse_args()

    events = run_pipeline(demo=args.demo, data_dir=Path(args.data_dir))

    print(f"\n{'='*70}")
    print(f"  Pipeline complete — {len(events)} compliance event(s) generated")
    print(f"{'='*70}\n")

    for e in events:
        print(
            f"  [{e.severity:8s}] {e.behavior_class:40s} "
            f"→ {e.escalation_action[:50]}"
        )
        print(f"           Sig: {e.signature[:16]}…\n")


if __name__ == "__main__":
    main()
