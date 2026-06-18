from pathlib import Path

from src.policy.parser import parse_policy_rules
from src.run_pipeline import run_pipeline


def test_policy_parser_extracts_four_unsafe_rules():
    rules = parse_policy_rules(Path("compliance_policy.pdf"))
    assert len(rules) == 4
    assert {rule.domain for rule in rules} == {
        "Pedestrian Movement",
        "Equipment Interaction",
        "Electrical Safety",
        "Forklift Load",
    }


def test_demo_pipeline_generates_required_event_fields():
    events = run_pipeline(demo=True)
    assert len(events) == 4
    first = events[0].to_dict()
    for field in [
        "event_id",
        "timestamp",
        "clip_id",
        "zone",
        "behavior_class",
        "policy_rule_ref",
        "event_description",
        "severity",
        "escalation_action",
    ]:
        assert first[field]
