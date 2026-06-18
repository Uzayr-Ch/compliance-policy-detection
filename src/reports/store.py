from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

from src.models import ComplianceEvent


ROOT = Path(__file__).resolve().parents[2]
OUTPUTS = ROOT / "outputs"
DB_PATH = OUTPUTS / "compliance_events.db"
JSONL_PATH = OUTPUTS / "audit_log.jsonl"
CSV_PATH = OUTPUTS / "audit_log.csv"

FIELDNAMES = [
    "event_id",
    "timestamp",
    "clip_id",
    "zone",
    "behavior_class",
    "policy_rule_ref",
    "event_description",
    "severity",
    "escalation_action",
    "confidence",
    "signature",
    "source_video",
]


def init_db(db_path: Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS compliance_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                clip_id TEXT NOT NULL,
                zone TEXT NOT NULL,
                behavior_class TEXT NOT NULL,
                policy_rule_ref TEXT NOT NULL,
                event_description TEXT NOT NULL,
                severity TEXT NOT NULL,
                escalation_action TEXT NOT NULL,
                confidence REAL NOT NULL,
                signature TEXT NOT NULL,
                source_video TEXT
            )
            """
        )


def append_event(event: ComplianceEvent, db_path: Path = DB_PATH) -> None:
    init_db(db_path)
    OUTPUTS.mkdir(parents=True, exist_ok=True)
    row = event.to_dict()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO compliance_events (
                event_id, timestamp, clip_id, zone, behavior_class, policy_rule_ref,
                event_description, severity, escalation_action, confidence, signature, source_video
            ) VALUES (
                :event_id, :timestamp, :clip_id, :zone, :behavior_class, :policy_rule_ref,
                :event_description, :severity, :escalation_action, :confidence, :signature, :source_video
            )
            """,
            row,
        )
    with JSONL_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")
    write_header = not CSV_PATH.exists()
    with CSV_PATH.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def load_events(db_path: Path = DB_PATH) -> list[dict]:
    if not db_path.exists():
        return []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM compliance_events ORDER BY timestamp DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def verify_audit_trail(db_path: Path = DB_PATH) -> list[dict]:
    """Loads all database records and recalculates their SHA-256 hashes to verify integrity."""
    events = load_events(db_path)
    report = []
    for e in events:
        # Reconstruct event for verification
        evt = ComplianceEvent(
            event_id=e["event_id"],
            timestamp=e["timestamp"],
            clip_id=e["clip_id"],
            zone=e["zone"],
            behavior_class=e["behavior_class"],
            policy_rule_ref=e["policy_rule_ref"],
            event_description=e["event_description"],
            severity=e["severity"],
            escalation_action=e["escalation_action"],
            confidence=e["confidence"],
            signature=e["signature"],
            source_video=e.get("source_video"),
        )
        report.append({
            "event_id": evt.event_id,
            "timestamp": evt.timestamp,
            "behavior_class": evt.behavior_class,
            "signature": evt.signature,
            "verified": evt.verify(),
        })
    return report
