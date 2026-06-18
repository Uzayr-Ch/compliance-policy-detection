"""
Comprehensive test suite for the Factory Compliance & Alert Escalation System.

Tests cover:
    - Policy PDF parsing and rule extraction
    - Severity matrix (base, context modifiers, temporal escalation)
    - Escalation routing
    - Cryptographic signature creation and verification
    - Report store (SQLite persistence, audit trail verification)
    - End-to-end demo pipeline
"""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from src.escalation.router import alert_required, route_for_severity
from src.models import (
    BehaviorRule,
    ComplianceEvent,
    DetectionRecord,
    calculate_signature,
    new_event_id,
    utc_now_iso,
)
from src.policy.parser import parse_policy_rules
from src.reports.store import append_event, init_db, load_events, verify_audit_trail
from src.run_pipeline import run_pipeline
from src.severity.matrix import categorize, _escalate


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def sample_rules() -> list[BehaviorRule]:
    return parse_policy_rules(Path("compliance_policy.pdf"))


@pytest.fixture()
def walkway_rule(sample_rules: list[BehaviorRule]) -> BehaviorRule:
    return next(r for r in sample_rules if r.unsafe_behavior == "Safe Walkway Violation")


@pytest.fixture()
def panel_rule(sample_rules: list[BehaviorRule]) -> BehaviorRule:
    return next(r for r in sample_rules if r.unsafe_behavior == "Opened Panel Cover")


@pytest.fixture()
def overload_rule(sample_rules: list[BehaviorRule]) -> BehaviorRule:
    return next(r for r in sample_rules if r.unsafe_behavior == "Carrying Overload with Forklift")


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_events.db"


# ── Policy Parser ────────────────────────────────────────────────────────────

class TestPolicyParser:
    def test_extracts_four_rules(self, sample_rules: list[BehaviorRule]):
        assert len(sample_rules) == 4

    def test_covers_all_domains(self, sample_rules: list[BehaviorRule]):
        domains = {r.domain for r in sample_rules}
        assert domains == {"Pedestrian Movement", "Equipment Interaction", "Electrical Safety", "Forklift Load"}

    def test_each_rule_has_policy_reference(self, sample_rules: list[BehaviorRule]):
        for rule in sample_rules:
            assert rule.policy_rule_ref.startswith("Section ")

    def test_hazard_signals_are_valid(self, sample_rules: list[BehaviorRule]):
        for rule in sample_rules:
            assert rule.hazard_signal in {"WARNING", "CRITICAL SAFETY NOTICE", "STANDARD"}

    def test_default_severities_are_valid(self, sample_rules: list[BehaviorRule]):
        from src.models import SEVERITIES
        for rule in sample_rules:
            assert rule.default_severity in SEVERITIES

    def test_rules_have_observable_indicators(self, sample_rules: list[BehaviorRule]):
        for rule in sample_rules:
            assert len(rule.observable_indicator) > 10


# ── Severity Matrix ─────────────────────────────────────────────────────────

class TestSeverityMatrix:
    def test_walkway_no_vehicle_is_medium(self, walkway_rule, sample_rules):
        det = DetectionRecord(
            clip_id="test.mp4", timestamp_seconds=1.0,
            behavior_class="Safe Walkway Violation",
            policy_rule_ref=walkway_rule.policy_rule_ref,
            observed_behavior="Person detected outside green walkway boundaries.",
            zone="Zone-1", confidence=0.9,
        )
        sev = categorize(det, sample_rules)
        assert sev == "MEDIUM"

    def test_walkway_with_forklift_is_high(self, walkway_rule, sample_rules):
        det = DetectionRecord(
            clip_id="test.mp4", timestamp_seconds=1.0,
            behavior_class="Safe Walkway Violation",
            policy_rule_ref=walkway_rule.policy_rule_ref,
            observed_behavior="Person outside walkway, forklift detected in transit corridor.",
            zone="Zone-1", confidence=0.9,
        )
        sev = categorize(det, sample_rules)
        assert sev == "HIGH"

    def test_panel_no_personnel_is_low(self, panel_rule, sample_rules):
        det = DetectionRecord(
            clip_id="test.mp4", timestamp_seconds=1.0,
            behavior_class="Opened Panel Cover",
            policy_rule_ref=panel_rule.policy_rule_ref,
            observed_behavior="Panel cover open. No personnel detected nearby.",
            zone="Zone-1", confidence=0.9,
        )
        sev = categorize(det, sample_rules)
        assert sev == "LOW"

    def test_panel_with_worker_is_high(self, panel_rule, sample_rules):
        det = DetectionRecord(
            clip_id="test.mp4", timestamp_seconds=1.0,
            behavior_class="Opened Panel Cover",
            policy_rule_ref=panel_rule.policy_rule_ref,
            observed_behavior="Panel cover open. Worker standing in proximity.",
            zone="Zone-1", confidence=0.9,
        )
        sev = categorize(det, sample_rules)
        assert sev == "HIGH"

    def test_critical_safety_notice_always_critical(self, overload_rule, sample_rules):
        det = DetectionRecord(
            clip_id="test.mp4", timestamp_seconds=1.0,
            behavior_class="Carrying Overload with Forklift",
            policy_rule_ref=overload_rule.policy_rule_ref,
            observed_behavior="Forklift carrying 3 blocks.",
            zone="Zone-1", confidence=0.9,
        )
        sev = categorize(det, sample_rules)
        assert sev == "CRITICAL"

    def test_temporal_escalation_within_window(self, walkway_rule, sample_rules):
        """Same-class event within 300s should bump MEDIUM → HIGH."""
        det = DetectionRecord(
            clip_id="test.mp4", timestamp_seconds=1.0,
            behavior_class="Safe Walkway Violation",
            policy_rule_ref=walkway_rule.policy_rule_ref,
            observed_behavior="Person outside walkway.",
            zone="Zone-1", confidence=0.9,
        )
        now = "2026-06-18T12:05:00Z"
        history = [
            {"behavior_class": "Safe Walkway Violation", "timestamp": "2026-06-18T12:03:00Z"},
        ]
        sev = categorize(det, sample_rules, recent_events=history, current_timestamp=now)
        assert sev == "HIGH"  # MEDIUM escalated to HIGH

    def test_no_escalation_outside_window(self, walkway_rule, sample_rules):
        det = DetectionRecord(
            clip_id="test.mp4", timestamp_seconds=1.0,
            behavior_class="Safe Walkway Violation",
            policy_rule_ref=walkway_rule.policy_rule_ref,
            observed_behavior="Person outside walkway.",
            zone="Zone-1", confidence=0.9,
        )
        now = "2026-06-18T12:10:00Z"
        history = [
            {"behavior_class": "Safe Walkway Violation", "timestamp": "2026-06-18T12:03:00Z"},
        ]
        sev = categorize(det, sample_rules, recent_events=history, current_timestamp=now)
        assert sev == "MEDIUM"  # 7 min gap > 300s window → no escalation

    def test_escalate_helper(self):
        assert _escalate("LOW") == "MEDIUM"
        assert _escalate("MEDIUM") == "HIGH"
        assert _escalate("HIGH") == "CRITICAL"
        assert _escalate("CRITICAL") == "CRITICAL"  # capped


# ── Escalation Router ───────────────────────────────────────────────────────

class TestEscalationRouter:
    def test_low_logs_only(self):
        action = route_for_severity("LOW")
        assert "Log" in action or "log" in action.lower()

    def test_medium_includes_email(self):
        action = route_for_severity("MEDIUM")
        assert "email" in action.lower() or "notification" in action.lower()

    def test_high_triggers_alert(self):
        assert alert_required("HIGH")

    def test_critical_triggers_alert(self):
        assert alert_required("CRITICAL")

    def test_low_no_alert(self):
        assert not alert_required("LOW")

    def test_medium_no_alert(self):
        assert not alert_required("MEDIUM")


# ── Cryptographic Signatures ─────────────────────────────────────────────────

class TestCryptographicSignatures:
    def test_signature_is_64_char_hex(self):
        sig = calculate_signature("id1", "2026-01-01T00:00:00Z", "clip.mp4",
                                  "Zone-1", "Test", "Section 1", "HIGH", "Alert")
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)

    def test_same_inputs_same_signature(self):
        args = ("id1", "2026-01-01T00:00:00Z", "clip.mp4", "Zone-1",
                "Test", "Section 1", "HIGH", "Alert")
        assert calculate_signature(*args) == calculate_signature(*args)

    def test_different_inputs_different_signature(self):
        sig1 = calculate_signature("id1", "ts", "c", "z", "b", "r", "HIGH", "a")
        sig2 = calculate_signature("id2", "ts", "c", "z", "b", "r", "HIGH", "a")
        assert sig1 != sig2

    def test_event_verify_passes(self):
        ts = utc_now_iso()
        evt_id = new_event_id()
        action = "test-action"
        sig = calculate_signature(evt_id, ts, "clip.mp4", "Zone-1",
                                  "Test", "Sec 1", "HIGH", action)
        evt = ComplianceEvent(
            event_id=evt_id, timestamp=ts, clip_id="clip.mp4", zone="Zone-1",
            behavior_class="Test", policy_rule_ref="Sec 1",
            event_description="desc", severity="HIGH",
            escalation_action=action, confidence=0.9, signature=sig,
        )
        assert evt.verify()

    def test_event_verify_fails_on_tamper(self):
        ts = utc_now_iso()
        evt_id = new_event_id()
        sig = calculate_signature(evt_id, ts, "clip.mp4", "Zone-1",
                                  "Test", "Sec 1", "HIGH", "act")
        evt = ComplianceEvent(
            event_id=evt_id, timestamp=ts, clip_id="clip.mp4", zone="Zone-1",
            behavior_class="Test", policy_rule_ref="Sec 1",
            event_description="desc", severity="LOW",  # tampered severity
            escalation_action="act", confidence=0.9, signature=sig,
        )
        assert not evt.verify()


# ── Report Store ─────────────────────────────────────────────────────────────

class TestReportStore:
    def test_init_creates_table(self, tmp_db: Path):
        init_db(tmp_db)
        with sqlite3.connect(tmp_db) as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        assert ("compliance_events",) in tables

    def test_append_and_load(self, tmp_db: Path):
        sig = calculate_signature("e1", "ts", "c", "z", "b", "r", "HIGH", "a")
        evt = ComplianceEvent(
            event_id="e1", timestamp="ts", clip_id="c", zone="z",
            behavior_class="b", policy_rule_ref="r",
            event_description="d", severity="HIGH",
            escalation_action="a", confidence=0.9, signature=sig,
        )
        append_event(evt, tmp_db)
        rows = load_events(tmp_db)
        assert len(rows) == 1
        assert rows[0]["event_id"] == "e1"

    def test_audit_trail_verification(self, tmp_db: Path):
        sig = calculate_signature("e2", "ts2", "c2", "z2", "b2", "r2", "LOW", "log")
        evt = ComplianceEvent(
            event_id="e2", timestamp="ts2", clip_id="c2", zone="z2",
            behavior_class="b2", policy_rule_ref="r2",
            event_description="d2", severity="LOW",
            escalation_action="log", confidence=0.85, signature=sig,
        )
        append_event(evt, tmp_db)
        report = verify_audit_trail(tmp_db)
        assert len(report) == 1
        assert report[0]["verified"] is True


# ── End-to-end Pipeline ─────────────────────────────────────────────────────

class TestPipeline:
    def test_demo_generates_four_events(self):
        events = run_pipeline(demo=True, persist=False)
        assert len(events) == 4

    def test_all_required_fields_present(self):
        events = run_pipeline(demo=True, persist=False)
        required = {
            "event_id", "timestamp", "clip_id", "zone",
            "behavior_class", "policy_rule_ref", "event_description",
            "severity", "escalation_action", "confidence", "signature",
        }
        for evt in events:
            d = evt.to_dict()
            for field in required:
                assert d.get(field), f"Missing or empty: {field}"

    def test_demo_produces_varied_severities(self):
        events = run_pipeline(demo=True, persist=False)
        severities = {e.severity for e in events}
        # Should NOT be all CRITICAL — the demo must produce a realistic mix
        assert len(severities) >= 2, f"All events same severity: {severities}"

    def test_all_signatures_verify(self):
        events = run_pipeline(demo=True, persist=False)
        for evt in events:
            assert evt.verify(), f"Signature mismatch for {evt.event_id}"
