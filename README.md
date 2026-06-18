# Factory Compliance & Alert Escalation System

This repository implements the Genesys AI intern take-home assessment: an end-to-end factory compliance pipeline that parses the provided OHS policy PDF, detects policy-defined violations from video inputs or annotations, classifies severity, routes alerts/logs, and exposes an operations dashboard.

## What Is Included

- **Module 1 - Detection Engine:** ingests `data/` clips or `data/manifest.json` annotations and emits structured detection records grounded in parsed policy rules.
- **Module 2 - Severity Matrix:** maps each violation to `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` using policy warning language and context.
- **Module 3 - Escalation Pipeline:** logs all events and triggers dashboard alerts for `HIGH` and `CRITICAL` events.
- **Module 4 - Reports:** writes immutable records to SQLite, JSONL, and CSV in `outputs/`.
- **Module 5 - Dashboard:** Streamlit GUI with live monitor, alert timeline, historical filtering, and CSV/JSON export.

## Repository Structure

```text
factory-compliance-system/
├── README.md
├── compliance_policy.pdf
├── data/
│   └── manifest_example.json
├── docs/
│   ├── Compliance_Policy_Manual.pdf
│   ├── Compliance_Policy_Manual.txt
│   ├── Intern_Assessment_AI.pdf
│   └── Intern_Assessment_AI.txt
├── outputs/
│   ├── audit_log.csv
│   ├── audit_log.jsonl
│   ├── compliance_events.db
│   └── policy_rules.json
├── src/
│   ├── detection/
│   ├── escalation/
│   ├── policy/
│   ├── reports/
│   ├── severity/
│   ├── dashboard/
│   ├── models.py
│   └── run_pipeline.py
├── tests/
└── requirements.txt
```

## Setup

```bash
python -m pip install -r requirements.txt
```

The implementation uses Python standard-library storage plus `pypdf` for policy extraction and Streamlit/Pandas for the dashboard.

## Run The Pipeline

Generate policy-grounded demo events:

```bash
python -m src.run_pipeline --demo
```

Process real inputs from `data/`:

```bash
python -m src.run_pipeline --data-dir data
```

The pipeline looks for inputs in this order:

1. `data/manifest.json`, matching the format in `data/manifest_example.json`.
2. Video files whose filenames contain policy-derived behavior hints such as `walkway_violation`, `unauthorized`, `open_panel`, or `forklift_overload`.
3. Demo mode when `--demo` is supplied.

## Run The Dashboard

```bash
streamlit run src/dashboard/app.py
```

The dashboard provides:

- live/simulated feed monitor with alert banners for `HIGH` and `CRITICAL` events;
- chronological alert timeline;
- historical event table with severity, behavior class, and zone filters;
- CSV and JSON export buttons for filtered records.

## Policy Parsing Approach

`src/policy/parser.py` reads `compliance_policy.pdf` using `pypdf`, extracts Sections 3-6, and builds `outputs/policy_rules.json`. Each rule contains:

- unsafe behavior;
- compliant behavior pair;
- observable indicator sentence;
- policy section reference;
- hazard signal such as `WARNING` or `CRITICAL SAFETY NOTICE`;
- default severity.

This keeps behavior classes traceable to the policy document rather than defining the detector categories independently.

## Severity Rationale

The policy contains two `WARNING` behaviors and two `CRITICAL SAFETY NOTICE` behaviors.

| Policy behavior | Policy signal | Severity used | Rationale |
| --- | --- | --- | --- |
| Safe Walkway Violation | WARNING | HIGH | Personnel outside green walkway boundaries are near machinery/forklift hazards and require immediate response. |
| Unauthorized Intervention | CRITICAL SAFETY NOTICE | CRITICAL | The policy says anyone interacting with equipment without the green vest must be assumed unauthorized. |
| Opened Panel Cover | WARNING | LOW by default | State-based unsafe condition; elevated by context if personnel exposure is present. Demo uses no nearby personnel. |
| Carrying Overload with Forklift | CRITICAL SAFETY NOTICE | CRITICAL | The block threshold is explicit: three or more blocks triggers immediate alert. |

## Detection Notes And Limitations

The workspace does not include the Kaggle video dataset, so the repository provides a deterministic demo mode and a manifest-based interface for real clip annotations. This makes the full pipeline runnable for reviewers immediately while preserving the contract expected by the assignment.

For a production-grade version, the detection module should be replaced or extended with a trained/zero-shot vision model that localizes people, forklift loads, electrical panels, vest colors, and walkway boundaries frame by frame. The downstream modules are model-agnostic and already accept structured detections with timestamps, zones, policy references, and confidence scores.

## Reports

Every detection generates a compliance event with the required fields:

- `event_id`
- `timestamp`
- `clip_id`
- `zone`
- `behavior_class`
- `policy_rule_ref`
- `event_description`
- `severity`
- `escalation_action`

Records are written to:

- `outputs/compliance_events.db`
- `outputs/audit_log.jsonl`
- `outputs/audit_log.csv`

## Tests

```bash
python -m pytest
```

The tests verify that the parser extracts the four policy-defined unsafe classes and that the demo pipeline generates complete compliance events.
