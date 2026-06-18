# Factory Compliance & Alert Escalation System

> End-to-end AI-powered factory safety compliance pipeline that parses OHS policy documents, detects violations from video surveillance, classifies severity with context-aware escalation, and delivers real-time alerts through an operations dashboard.

## Assessment Requirement Mapping

| Requirement | Implementation |
| --- | --- |
| Structured GitHub repository | Modular `src/` package with `tests/`, `docs/`, `notebooks/`, `outputs/` |
| Policy parsing | `src/policy/parser.py` — dynamic regex extraction from `compliance_policy.pdf` |
| Detection engine | `src/detection/engine.py` — YOLOv8 + OpenCV vision pipeline with mock fallback |
| Severity classification | `src/severity/matrix.py` — 3-layer: base → context modifiers → temporal escalation |
| Alert escalation | `src/escalation/router.py` — tiered EHS dispatch actions per severity |
| Automated reports | `src/reports/store.py` — SHA-256 signed records in SQLite + JSONL + CSV |
| Operations dashboard | `src/dashboard/app.py` — Streamlit control center with 5 operational tabs |
| Kaggle dataset workflow | `notebooks/kaggle_workflow.ipynb` + `src/detection/kaggle_manifest.py` |

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    COMPLIANCE PIPELINE                          │
│                                                                 │
│  ┌──────────┐    ┌──────────┐   ┌──────────┐    ┌──────────┐    │
│  │  Policy  │    │Detection │   │ Severity │    │Escalation│    │
│  │  Parser  │──▶│  Engine  │──▶│  Matrix  │──▶│  Router  │    │
│  │ (pypdf   │    │(YOLOv8)  │   │(3-layer) │    │(dispatch)│    │
│  └──────────┘    └──────────┘   └──────────┘    └──────────┘    │
│       │                                              │          │
│       ▼                                              ▼          │
│  policy_rules.json                          ComplianceEvent     │
│                                             + SHA-256 sig       │
│                                                    │            │
│                                       ┌────────────┼──────┐     │
│                                       ▼            ▼      ▼     │
│                                  SQLite DB    JSONL     CSV     │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              STREAMLIT OPERATIONS DASHBOARD              │   │
│  │  Live Monitor │ Analytics │ Timeline │ Audit │ History   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Repository Structure

```text
factory-compliance-system/
├── README.md
├── compliance_policy.pdf          # OHS policy document (input)
├── requirements.txt               # Python dependencies
├── data/
│   └── manifest_example.json      # Sample detection manifest
├── notebooks/
│   └── kaggle_workflow.ipynb      # Kaggle GPU processing notebook
├── outputs/
│   ├── policy_rules.json          # Extracted policy rules
│   ├── compliance_events.db       # SQLite audit database
│   ├── audit_log.jsonl            # Append-only JSON Lines log
│   ├── audit_log.csv              # CSV audit export
│   └── annotated/                 # YOLOv8-annotated video clips
├── src/
│   ├── models.py                  # Core dataclasses + SHA-256 utilities
│   ├── run_pipeline.py            # End-to-end pipeline orchestrator
│   ├── policy/
│   │   └── parser.py              # Dynamic PDF rule extractor
│   ├── detection/
│   │   ├── engine.py              # YOLOv8 + OpenCV detection engine
│   │   └── kaggle_manifest.py     # Kaggle dataset manifest builder
│   ├── severity/
│   │   └── matrix.py              # Context-aware severity classifier
│   ├── escalation/
│   │   └── router.py              # Tiered dispatch action router
│   ├── reports/
│   │   └── store.py               # Triple-format audit trail writer
│   └── dashboard/
│       └── app.py                 # Streamlit operations dashboard
└── tests/
    └── test_policy_pipeline.py    # 32 unit + integration tests
```

## Quick Start

### 1. Setup

```bash
python -m venv venv
# Windows
.\venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Run the Pipeline

```bash
# Demo mode (synthetic detections, works without any video files)
python -m src.run_pipeline --demo

# Process real video clips from data/ directory
python -m src.run_pipeline --data-dir data
```

**Example output:**
```
======================================================================
  Pipeline complete — 4 compliance event(s) generated
======================================================================

  [HIGH    ] Safe Walkway Violation          → Log + SMS alert to EHS coordinator + floor alarm activation
  [CRITICAL] Unauthorized Intervention       → Log + emergency dispatch to safety response team + ...
  [LOW     ] Opened Panel Cover              → Log to compliance database
  [CRITICAL] Carrying Overload with Forklift → Log + emergency dispatch to safety response team + ...
```

### 3. Launch the Dashboard

```bash
streamlit run src/dashboard/app.py
```

### 4. Run Tests

```bash
python -m pytest -v
```

## Key Technical Features

### Dynamic PDF Policy Parsing

`src/policy/parser.py` reads `compliance_policy.pdf` and uses regex pattern matching to **dynamically** locate and extract:
- Section boundaries (`SECTION N —`)
- Required vs. non-compliant behavior pairs
- Observable indicator sentences
- Hazard signal levels (`WARNING`, `CRITICAL SAFETY NOTICE`)

This ensures the parser adapts automatically if the policy document structure changes — no hardcoded page numbers or indices.

### Computer Vision Pipeline (YOLOv8 + OpenCV)

`src/detection/engine.py` integrates **ultralytics YOLOv8** and **OpenCV** for frame-by-frame video analysis:

| Violation Type | Visual Annotation |
| --- | --- |
| Safe Walkway Violation | Green corridor overlay; red bounding box labeled `Violator (Outside Walkway)` for persons outside |
| Unauthorized Intervention | Machinery zone boundary; red label `Unauthorized (Red-Black Vest)` for non-green-vest workers |
| Opened Panel Cover | Red outline around open panel doors with blinking indicator |
| Carrying Overload with Forklift | Counts detected boxes on forklifts; red label `Forklift Overloaded` when ≥ 3 |

The engine gracefully falls back to manifest-based or demo detection when vision libraries are unavailable.

### Three-Layer Severity Classification

`src/severity/matrix.py` applies severity in three sequential layers:

1. **Base severity** — from the policy rule's `default_severity` (extracted from the PDF)
2. **Context modifiers** — inspects detection descriptions for proximity signals:
   - Walkway: "forklift nearby" → escalate MEDIUM → HIGH
   - Panel: "worker in proximity" → escalate LOW → HIGH (with negation-aware NLP)
3. **Temporal escalation** — if the same violation class recurs within a 300-second window, severity bumps one tier (e.g. MEDIUM → HIGH)

| Policy Behavior | Base Severity | Context Escalation | Temporal Escalation |
| --- | --- | --- | --- |
| Safe Walkway Violation | MEDIUM | → HIGH if vehicles nearby | → HIGH/CRITICAL on recurrence |
| Unauthorized Intervention | CRITICAL | Always CRITICAL | Capped at CRITICAL |
| Opened Panel Cover | LOW | → HIGH if workers nearby | → MEDIUM on recurrence |
| Carrying Overload with Forklift | CRITICAL | Always CRITICAL | Capped at CRITICAL |

### Immutable Cryptographic Audit Trail

Every `ComplianceEvent` receives a **SHA-256 integrity signature** computed over its core fields:

```
SHA256(event_id ‖ timestamp ‖ clip_id ‖ zone ‖ behavior_class ‖ policy_rule_ref ‖ severity ‖ escalation_action)
```

The signature is stored alongside the record in all three output formats (SQLite, JSONL, CSV). The dashboard's **Audit Integrity** tab recalculates signatures on demand to verify that no records have been tampered with.

### Tiered Escalation Dispatch

`src/escalation/router.py` maps each severity to realistic EHS response protocols:

| Severity | Dispatch Action |
| --- | --- |
| LOW | Log to compliance database |
| MEDIUM | Log + email notification to shift supervisor |
| HIGH | Log + SMS alert to EHS coordinator + floor alarm activation |
| CRITICAL | Log + emergency dispatch + production line halt + siren + strobe |

### Operations Dashboard

The Streamlit dashboard provides five operational views:

- **📺 Live Monitor** — Latest incident details with video playback, severity badges, and escalation actions
- **📊 Analytics** — KPI metric cards (total/critical/high/safe) and violation frequency charts
- **🕒 Alert Timeline** — Chronological dispatch log with column-configured data table
- **🛡️ Audit Integrity** — Real-time SHA-256 signature verification with pass/fail indicators
- **🗄️ Historical Logs** — Multi-filter query panel with CSV/JSON export

When HIGH or CRITICAL events are active, the dashboard displays **flashing strobe alert banners** and plays a **browser-native auditory siren** (Web Audio API).

## Kaggle Workflow

The Kaggle dataset (`trnhhnggiang/video-dataset-for-safe-and-unsafe-behaviours`) is ~10GB and should be processed on Kaggle's free GPU infrastructure:

1. Create a Kaggle Notebook and attach the dataset
2. Clone this repository and install dependencies
3. Run `python -m src.detection.kaggle_manifest --dataset-root /kaggle/input --limit-per-class 3`
4. Run `python -m src.run_pipeline --data-dir data`
5. Download the generated `outputs/` and commit to GitHub

Detailed steps are in `notebooks/kaggle_workflow.ipynb`.

## Test Coverage

The test suite (`tests/test_policy_pipeline.py`) contains **32 tests** organized into 6 test classes:

| Test Class | Tests | Covers |
| --- | --- | --- |
| `TestPolicyParser` | 6 | Rule extraction, domains, references, hazard signals |
| `TestSeverityMatrix` | 8 | Context modifiers, negation handling, temporal escalation |
| `TestEscalationRouter` | 6 | Dispatch actions, alert thresholds |
| `TestCryptographicSignatures` | 5 | SHA-256 computation, verification, tamper detection |
| `TestReportStore` | 3 | SQLite persistence, audit trail validation |
| `TestPipeline` | 4 | End-to-end demo, field completeness, severity variance |

```bash
$ python -m pytest -v
================================ 32 passed in 15s ================================
```
