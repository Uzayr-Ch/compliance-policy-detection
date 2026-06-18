from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


VIDEO_EXTENSIONS = {".mp4", ".avi", ".mov", ".mkv", ".webm"}

BEHAVIOR_PATTERNS = {
    "Safe Walkway Violation": (
        "walkway violation",
        "unsafe walkway",
        "outside walkway",
        "pedestrian",
        "walking",
        "walkway",
    ),
    "Unauthorized Intervention": (
        "unauthorized intervention",
        "unauthorised intervention",
        "without green vest",
        "red black",
        "red-black",
        "intervention",
        "machine",
    ),
    "Opened Panel Cover": (
        "opened panel",
        "open panel",
        "panel cover",
        "electrical panel",
        "panel",
    ),
    "Carrying Overload with Forklift": (
        "forklift overload",
        "overload",
        "three blocks",
        "3 blocks",
        "forklift",
        "carrying",
    ),
}

DEFAULT_DESCRIPTIONS = {
    "Safe Walkway Violation": "Person detected outside the green-marked designated safe walkway boundary.",
    "Unauthorized Intervention": "Person appears to be interacting with production equipment without the green authorization vest indicator.",
    "Opened Panel Cover": "Electrical panel cover appears open during production operations.",
    "Carrying Overload with Forklift": "Forklift load appears to exceed the safe threshold of two standardized blocks.",
}


def normalize(text: str) -> str:
    text = text.replace("_", " ").replace("-", " ")
    return re.sub(r"\s+", " ", text.lower()).strip()


def infer_behavior(video_path: Path) -> str | None:
    haystack = normalize(" ".join(video_path.parts[-5:]))
    for behavior, patterns in BEHAVIOR_PATTERNS.items():
        if any(pattern in haystack for pattern in patterns):
            return behavior
    return None


def find_videos(dataset_root: Path) -> list[Path]:
    return sorted(
        path
        for path in dataset_root.rglob("*")
        if path.is_file() and path.suffix.lower() in VIDEO_EXTENSIONS
    )


def build_manifest(
    dataset_root: Path,
    output_path: Path,
    limit_per_class: int,
    include_unmatched_report: bool = True,
) -> dict:
    counts = {behavior: 0 for behavior in BEHAVIOR_PATTERNS}
    events: list[dict] = []
    unmatched: list[str] = []

    for video_path in find_videos(dataset_root):
        behavior = infer_behavior(video_path)
        if behavior is None:
            unmatched.append(str(video_path))
            continue
        if counts[behavior] >= limit_per_class:
            continue

        counts[behavior] += 1
        events.append(
            {
                "clip_id": video_path.name,
                "video": str(video_path),
                "timestamp_seconds": 1.0,
                "behavior_class": behavior,
                "observed_behavior": DEFAULT_DESCRIPTIONS[behavior],
                "zone": f"Zone-{len(events) + 1}",
                "confidence": 0.75,
            }
        )

    manifest = {
        "source": str(dataset_root),
        "notes": (
            "Auto-generated on Kaggle from dataset file/folder names. "
            "Review behavior_class values before using for final reporting."
        ),
        "events": events,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    if include_unmatched_report:
        report_path = output_path.with_name("unmatched_videos.txt")
        report_path.write_text("\n".join(unmatched[:500]), encoding="utf-8")

    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create data/manifest.json from Kaggle dataset video paths."
    )
    parser.add_argument(
        "--dataset-root",
        default="/kaggle/input",
        help="Root directory where Kaggle attaches datasets.",
    )
    parser.add_argument(
        "--output",
        default="data/manifest.json",
        help="Manifest path consumed by src.run_pipeline.",
    )
    parser.add_argument(
        "--limit-per-class",
        type=int,
        default=3,
        help="Maximum sample videos to include for each policy behavior class.",
    )
    args = parser.parse_args()

    manifest = build_manifest(
        dataset_root=Path(args.dataset_root),
        output_path=Path(args.output),
        limit_per_class=args.limit_per_class,
    )
    print(f"Wrote {len(manifest['events'])} event(s) to {args.output}")
    for event in manifest["events"]:
        print(f"- {event['behavior_class']}: {event['clip_id']}")


if __name__ == "__main__":
    main()
