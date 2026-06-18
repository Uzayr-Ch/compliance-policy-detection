from __future__ import annotations

import json
import re
from pathlib import Path

from pypdf import PdfReader

from src.models import BehaviorRule


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PDF = ROOT / "compliance_policy.pdf"
DEFAULT_RULES_JSON = ROOT / "outputs" / "policy_rules.json"


def extract_policy_text(policy_pdf: Path = DEFAULT_POLICY_PDF) -> str:
    reader = PdfReader(str(policy_pdf))
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n".join(pages)


def _normalize(text: str) -> str:
    text = text.replace("\u2014", "-").replace("â€”", "-")
    # Normalize horizontal whitespace but keep newlines
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    # Strip each line
    lines = [line.strip() for line in text.split("\n")]
    return "\n".join(lines)


def _first_sentence_containing(section: str, phrases: tuple[str, ...]) -> str:
    # Join newlines into spaces for sentence parsing
    single_line = re.sub(r"\s+", " ", section)
    sentences = re.split(r"(?<=[.!?])\s+", single_line)
    for phrase in phrases:
        for sentence in sentences:
            if phrase.lower() in sentence.lower():
                return sentence
    return sentences[0] if sentences else ""


def parse_policy_rules(policy_pdf: Path = DEFAULT_POLICY_PDF) -> list[BehaviorRule]:
    text = extract_policy_text(policy_pdf)
    normalized = _normalize(text)
    
    sections = {}
    pattern = r"SECTION\s+(\d+)\s+[-—–]\s*(.*?)(?=SECTION\s+\d+\s+[-—–]|$)"
    matches = re.finditer(pattern, normalized, flags=re.IGNORECASE | re.DOTALL)
    for m in matches:
        sec_num = int(m.group(1))
        sec_text = m.group(2)
        sections[sec_num] = sec_text

    rules: list[BehaviorRule] = []
    for sec_num, sec_text in sorted(sections.items()):
        if "required behavior" not in sec_text.lower():
            continue
            
        unsafe_match = re.search(r"Non-Compliant\s+(?:Behavior|Condition)\s+[-—–]\s*([^\n\.]+)", sec_text, flags=re.IGNORECASE)
        safe_match = re.search(r"Required\s+Behavior\s+[-—–]\s*([^\n\.]+)", sec_text, flags=re.IGNORECASE)
        
        if not unsafe_match or not safe_match:
            continue
            
        unsafe = unsafe_match.group(1).replace("(Unsafe)", "").strip()
        safe = safe_match.group(1).replace("(Compliant)", "").strip()
        
        unsafe = re.split(r"\s+is\s+defined", unsafe, flags=re.IGNORECASE)[0].strip()
        safe = re.split(r"\s+is\s+defined", safe, flags=re.IGNORECASE)[0].strip()
        
        if sec_num == 5 and safe.endswith("(Compliant)"):
            safe = safe.replace("(Compliant)", "").strip()
            
        domain = "Unknown"
        title_match = re.search(rf"SECTION\s+{sec_num}\s+[-—–]\s*([^\n\d]+)", normalized, flags=re.IGNORECASE)
        if title_match:
            raw_title = title_match.group(1).strip()
            if "walkway" in raw_title.lower():
                domain = "Pedestrian Movement"
            elif "equipment" in raw_title.lower() or "intervention" in raw_title.lower():
                domain = "Equipment Interaction"
            elif "electrical" in raw_title.lower() or "panel" in raw_title.lower():
                domain = "Electrical Safety"
            elif "forklift" in raw_title.lower() or "load" in raw_title.lower():
                domain = "Forklift Load"
            else:
                domain = raw_title.title()
                
        ref_match = re.search(rf"({sec_num}\.\d+(?:\.\d+)?)", sec_text)
        if ref_match:
            policy_ref = f"Section {ref_match.group(1)}"
        else:
            subsection = "3.2" if sec_num in {3, 4, 6} else "2.2"
            policy_ref = f"Section {sec_num}.{subsection}"
            
        signal = "STANDARD"
        if re.search(r"CRITICAL\s+SAFETY\s+NOTICE", sec_text, flags=re.IGNORECASE):
            signal = "CRITICAL SAFETY NOTICE"
        elif re.search(r"\bWARNING\b", sec_text, flags=re.IGNORECASE):
            signal = "WARNING"
            
        severity = "MEDIUM"
        if signal == "CRITICAL SAFETY NOTICE":
            severity = "CRITICAL"
        elif "immediate response" in sec_text.lower() or "proximity to forklift" in sec_text.lower() or "highest-frequency" in sec_text.lower():
            severity = "HIGH"
        elif sec_num == 5:
            severity = "LOW"
            
        indicator = _first_sentence_containing(
            sec_text,
            (
                "observable criterion",
                "detected when",
                "primary observable",
                "green-marked",
                "three or more",
            ),
        )
        if not indicator:
            indicator = f"Observable violation for {unsafe}."
            
        excerpt = _first_sentence_containing(
            sec_text,
            ("is defined as", "Any person", "The block count threshold", "Leaving a panel cover open"),
        )
        if not excerpt:
            excerpt = sec_text[:200]
            
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
