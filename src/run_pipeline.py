from __future__ import annotations

import argparse
from pathlib import Path

from src.detection.engine import detect_violations
from src.escalation.router import route_for_severity
from src.models import ComplianceEvent, new_event_id, utc_now_iso
from src.policy.parser import load_rules, write_rules_json
from src.reports.store import append_event, init_db
from src.severity.matrix import categorize


def run_pipeline(demo: bool = False, data_dir: Path | None = None) -> list[ComplianceEvent]:
    rules = write_rules_json()
    detections = detect_violations(rules, data_dir=data_dir or Path("data"), demo=demo)
    init_db()
    events: list[ComplianceEvent] = []
    for detection in detections:
        severity = categorize(detection, rules)
        event = ComplianceEvent(
            event_id=new_event_id(),
            timestamp=utc_now_iso(),
            clip_id=detection.clip_id,
            zone=detection.zone,
            behavior_class=detection.behavior_class,
            policy_rule_ref=detection.policy_rule_ref,
            event_description=detection.observed_behavior,
            severity=severity,
            escalation_action=route_for_severity(severity),
            confidence=detection.confidence,
            source_video=detection.source_video,
        )
        append_event(event)
        events.append(event)
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the factory compliance pipeline.")
    parser.add_argument("--demo", action="store_true", help="Generate deterministic demo detections.")
    parser.add_argument("--data-dir", default="data", help="Directory containing input video clips.")
    args = parser.parse_args()
    events = run_pipeline(demo=args.demo, data_dir=Path(args.data_dir))
    print(f"Generated {len(events)} compliance event(s).")
    for event in events:
        print(f"{event.severity:8} {event.behavior_class} -> {event.escalation_action}")


if __name__ == "__main__":
    main()
