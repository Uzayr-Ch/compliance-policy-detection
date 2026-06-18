from __future__ import annotations

import json
import re
from pathlib import Path

from src.models import BehaviorRule, DetectionRecord


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
VIDEO_EXTENSIONS = {".mp4", ".avi", ".mov", ".mkv", ".webm"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _aliases(rule: BehaviorRule) -> set[str]:
    words = _slug(rule.unsafe_behavior).split("_")
    aliases = {_slug(rule.unsafe_behavior), "_".join(words[:2]), words[-1]}
    if "walkway" in words:
        aliases.update({"walkway_violation", "unsafe_walkway", "outside_walkway"})
    if "intervention" in words:
        aliases.update({"unauthorized", "red_black_vest", "no_green_vest"})
    if "panel" in words:
        aliases.update({"open_panel", "opened_panel", "panel_cover"})
    if "forklift" in words:
        aliases.update({"forklift_overload", "overload", "three_blocks"})
    return {alias for alias in aliases if alias}


def _from_manifest(data_dir: Path, rules: list[BehaviorRule]) -> list[DetectionRecord]:
    manifest = data_dir / "manifest.json"
    if not manifest.exists():
        return []
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    records: list[DetectionRecord] = []
    for item in raw.get("events", raw if isinstance(raw, list) else []):
        behavior = item.get("behavior_class") or item.get("unsafe_behavior")
        rule = next((rule for rule in rules if rule.unsafe_behavior == behavior), None)
        if not rule:
            continue
        records.append(
            DetectionRecord(
                clip_id=item.get("clip_id", item.get("video", "manual-event")),
                timestamp_seconds=float(item.get("timestamp_seconds", 0)),
                behavior_class=rule.unsafe_behavior,
                policy_rule_ref=rule.policy_rule_ref,
                observed_behavior=item.get("observed_behavior", rule.observable_indicator),
                zone=item.get("zone", "Zone-1"),
                confidence=float(item.get("confidence", 0.9)),
                source_video=item.get("video"),
            )
        )
    return records


def _from_video_names(data_dir: Path, rules: list[BehaviorRule]) -> list[DetectionRecord]:
    records: list[DetectionRecord] = []
    for video in sorted(data_dir.glob("*")):
        if video.suffix.lower() not in VIDEO_EXTENSIONS:
            continue
        name = _slug(video.stem)
        for rule in rules:
            if any(alias in name for alias in _aliases(rule)):
                records.append(
                    DetectionRecord(
                        clip_id=video.name,
                        timestamp_seconds=1.0,
                        behavior_class=rule.unsafe_behavior,
                        policy_rule_ref=rule.policy_rule_ref,
                        observed_behavior=f"Filename and dataset label indicate: {rule.observable_indicator}",
                        zone="Zone-1",
                        confidence=0.72,
                        source_video=str(video),
                    )
                )
                break
    return records


def _demo_records(rules: list[BehaviorRule]) -> list[DetectionRecord]:
    records: list[DetectionRecord] = []
    for index, rule in enumerate(rules, start=1):
        detail = rule.observable_indicator
        if rule.domain == "Electrical Safety":
            detail = f"{detail} No personnel nearby at the sampled time."
        records.append(
            DetectionRecord(
                clip_id=f"demo_clip_{index:02d}.mp4",
                timestamp_seconds=float(index * 2),
                behavior_class=rule.unsafe_behavior,
                policy_rule_ref=rule.policy_rule_ref,
                observed_behavior=detail,
                zone=f"Zone-{index}",
                confidence=0.85,
                source_video=None,
            )
        )
    return records


def detect_violations(
    rules: list[BehaviorRule], data_dir: Path = DATA_DIR, demo: bool = False
) -> list[DetectionRecord]:
    data_dir.mkdir(parents=True, exist_ok=True)
    manifest_records = _from_manifest(data_dir, rules)
    if manifest_records:
        return manifest_records
    video_records = _from_video_names(data_dir, rules)
    if video_records:
        return video_records
    if demo:
        return _demo_records(rules)
    return []
