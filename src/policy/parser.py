from __future__ import annotations

import json
import re
from pathlib import Path

from pypdf import PdfReader

from src.models import BehaviorRule


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PDF = ROOT / "compliance_policy.pdf"
DEFAULT_RULES_JSON = ROOT / "outputs" / "policy_rules.json"


SECTION_DOMAINS = {
    3: "Pedestrian Movement",
    4: "Equipment Interaction",
    5: "Electrical Safety",
    6: "Forklift Load",
}


def extract_policy_text(policy_pdf: Path = DEFAULT_POLICY_PDF) -> str:
    reader = PdfReader(str(policy_pdf))
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n".join(pages)


def _normalize(text: str) -> str:
    text = text.replace("\u2014", "-").replace("â€”", "-")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _section(text: str, section_number: int) -> str:
    pattern = rf"SECTION {section_number}\s+-.*?(?=SECTION {section_number + 1}\s+-|$)"
    match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
    return match.group(0) if match else ""


def _heading(section: str, heading_kind: str) -> str:
    pattern = rf"{heading_kind}.*?-\s*(.+?)(?=\s+(?:Safe|An?|The|Closed|Opened|Carrying)\s+.+?\s+is defined|\s*$)"
    match = re.search(pattern, section, flags=re.IGNORECASE)
    return _normalize(match.group(1)) if match else ""


def _first_sentence_containing(section: str, phrases: tuple[str, ...]) -> str:
    cleaned = _normalize(section)
    sentences = re.split(r"(?<=[.!?])\s+", cleaned)
    for phrase in phrases:
        for sentence in sentences:
            if phrase.lower() in sentence.lower():
                return sentence
    return sentences[0] if sentences else ""


def _hazard_signal(section: str) -> str:
    if re.search(r"CRITICAL\s+SAFETY\s+NOTICE", section, flags=re.IGNORECASE):
        return "CRITICAL SAFETY NOTICE"
    if re.search(r"\bWARNING\b", section, flags=re.IGNORECASE):
        return "WARNING"
    return "STANDARD"


def _default_severity(section_number: int, hazard_signal: str, section: str) -> str:
    if hazard_signal == "CRITICAL SAFETY NOTICE":
        return "CRITICAL"
    if "immediate response" in section.lower() or "proximity to forklift" in section.lower():
        return "HIGH"
    if section_number == 5:
        return "LOW"
    return "MEDIUM"


def parse_policy_rules(policy_pdf: Path = DEFAULT_POLICY_PDF) -> list[BehaviorRule]:
    text = extract_policy_text(policy_pdf)
    normalized = _normalize(text)
    rules: list[BehaviorRule] = []

    for section_number, domain in SECTION_DOMAINS.items():
        section = _section(normalized, section_number)
        if not section:
            continue

        unsafe = _heading(section, r"Non-Compliant (?:Behavior|Condition)")
        safe = _heading(section, r"Required Behavior")
        if section_number == 5 and safe.endswith("(Compliant)"):
            safe = safe.replace("(Compliant)", "").strip()
        unsafe = unsafe.replace("(Unsafe)", "").strip()

        indicator = _first_sentence_containing(
            section,
            (
                "observable criterion",
                "detected when",
                "primary observable",
                "green-marked",
                "three or more",
            ),
        )
        excerpt = _first_sentence_containing(
            section,
            ("is defined as", "Any person", "The block count threshold", "Leaving a panel cover open"),
        )
        signal = _hazard_signal(section)
        severity = _default_severity(section_number, signal, section)

        subsection = "3.2" if section_number in {3, 4, 6} else "2.2"
        policy_ref = f"Section {section_number}.{subsection}"
        rules.append(
            BehaviorRule(
                class_id=len(rules),
                domain=domain,
                unsafe_behavior=unsafe,
                safe_behavior=safe,
                observable_indicator=indicator,
                policy_rule_ref=policy_ref,
                hazard_signal=signal,
                default_severity=severity,
                source_excerpt=excerpt,
            )
        )

    return rules


def write_rules_json(
    policy_pdf: Path = DEFAULT_POLICY_PDF, output_path: Path = DEFAULT_RULES_JSON
) -> list[BehaviorRule]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rules = parse_policy_rules(policy_pdf)
    output_path.write_text(
        json.dumps([rule.to_dict() for rule in rules], indent=2), encoding="utf-8"
    )
    return rules


def load_rules(rules_path: Path = DEFAULT_RULES_JSON) -> list[BehaviorRule]:
    if not rules_path.exists():
        return write_rules_json(output_path=rules_path)
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    return [BehaviorRule(**item) for item in data]


if __name__ == "__main__":
    for rule in write_rules_json():
        print(f"{rule.class_id}: {rule.unsafe_behavior} -> {rule.default_severity}")
