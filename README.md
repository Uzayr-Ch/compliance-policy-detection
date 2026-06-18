# Factory Compliance & Alert Escalation System

This repository implements the Genesys AI intern take-home assessment: an end-to-end factory compliance pipeline that parses the provided OHS policy PDF, detects policy-defined violations from video inputs or annotations, classifies severity, routes alerts/logs, and exposes an operations dashboard.

## Assessment Requirement Mapping

| Requirement | Implemented in this repo |
| --- | --- |
| Structured GitHub repository | `README.md`, `compliance_policy.pdf`, `data/`, `src/`, `outputs/`, `requirements.txt`, `tests/` |
| Policy parsing | `src/policy/parser.py` extracts the four policy rules from `compliance_policy.pdf` |
| Detection engine | `src/detection/engine.py` consumes real `data/manifest.json`, labelled video names, or demo inputs |
| Severity matrix | `src/severity/matrix.py` assigns `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| Escalation pipeline | `src/escalation/router.py` routes low/medium to DB log and high/critical to alert + DB log |
| Automated reports | `src/reports/store.py` writes SQLite, JSONL, and CSV audit records |
| Operations dashboard | `src/dashboard/app.py` provides live monitor, timeline, filters, and export |
| Kaggle dataset workflow | `notebooks/kaggle_workflow.ipynb` and `src/detection/kaggle_manifest.py` |

## Recommended Submission Plan

The Kaggle dataset is large, so the practical workflow is:

1. Keep the full required repo structure on GitHub.
2. Use Kaggle Notebook only for heavy dataset access and sample processing.
3. Generate `data/manifest.json` and `outputs/` on Kaggle.
4. Download the generated output zip from Kaggle.
5. Copy those generated files back into this repo.
6. Commit and push this repository to GitHub.
7. Submit the GitHub repo link in the Genesys form.

This satisfies the requirement that the assessment be submitted as a structured GitHub repository while avoiding a local 10GB dataset download.

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
├── notebooks/
│   └── kaggle_workflow.ipynb
├── outputs/
│   ├── audit_log.csv
│   ├── audit_log.jsonl
│   ├── compliance_events.db
│   └── policy_rules.json
├── src/
│   ├── dashboard/
│   ├── detection/
│   ├── escalation/
│   ├── policy/
│   ├── reports/
│   ├── severity/
│   ├── models.py
│   └── run_pipeline.py
├── tests/
└── requirements.txt
```

## Local Setup

```bash
python -m pip install -r requirements.txt
```

The implementation uses Python standard-library storage plus `pypdf` for policy extraction and Streamlit/Pandas for the dashboard.

## Run Locally

Generate policy-grounded demo events:

```bash
python -m src.run_pipeline --demo
```

Process real or Kaggle-generated manifest inputs from `data/`:

```bash
python -m src.run_pipeline --data-dir data
```

Run the dashboard:

```bash
streamlit run src/dashboard/app.py
```

The dashboard provides:

- live/simulated feed monitor with alert banners for `HIGH` and `CRITICAL` events;
- chronological alert timeline;
- historical event table with severity, behavior class, and zone filters;
- CSV and JSON export buttons for filtered records.

## Kaggle Workflow

Use Kaggle because the dataset is already hosted there and does not need to be downloaded locally.

1. Create a Kaggle Notebook.
2. Attach this dataset from the Kaggle sidebar:

```text
trnhhnggiang/video-dataset-for-safe-and-unsafe-behaviours
```

3. Clone this GitHub repository inside the Kaggle Notebook:

```bash
git clone https://github.com/YOUR_USERNAME/factory-compliance-system.git
cd factory-compliance-system
pip install -r requirements.txt
```

4. Inspect the dataset paths:

```python
from pathlib import Path

videos = []
for ext in ["*.mp4", "*.avi", "*.mov", "*.mkv", "*.webm"]:
    videos.extend(Path("/kaggle/input").rglob(ext))

print(len(videos))
print(videos[:20])
```

5. Generate a sample manifest from Kaggle dataset videos:

```bash
python -m src.detection.kaggle_manifest \
  --dataset-root /kaggle/input \
  --limit-per-class 3 \
  --output data/manifest.json
```

6. Run the full pipeline on the Kaggle-generated manifest:

```bash
python -m src.run_pipeline --data-dir data
```

7. Package outputs for GitHub:

```bash
zip -r kaggle_outputs.zip data/manifest.json outputs
```

Download `kaggle_outputs.zip`, copy its contents into this repository locally, then commit and push.

The same steps are provided in `notebooks/kaggle_workflow.ipynb`.

## Push To GitHub

After creating an empty GitHub repository, run these commands locally from the repo root:

```bash
git remote add origin https://github.com/YOUR_USERNAME/factory-compliance-system.git
git branch -M main
git push -u origin main
```

If you update outputs after running Kaggle:

```bash
git add data/manifest.json outputs README.md notebooks src
git commit -m "Add Kaggle dataset processing outputs"
git push
```

## Policy Parsing Approach

`src/policy/parser.py` reads `compliance_policy.pdf`, extracts Sections 3-6, and builds `outputs/policy_rules.json`. Each rule contains:

- unsafe behavior;
- compliant behavior pair;
- observable indicator sentence;
- policy section reference;
- hazard signal such as `WARNING` or `CRITICAL SAFETY NOTICE`;
- default severity.

This keeps behavior classes traceable to the policy document rather than defining detector categories independently.

## Severity Rationale

The policy contains two `WARNING` behaviors and two `CRITICAL SAFETY NOTICE` behaviors.

| Policy behavior | Policy signal | Severity used | Rationale |
| --- | --- | --- | --- |
| Safe Walkway Violation | WARNING | HIGH | Personnel outside green walkway boundaries are near machinery/forklift hazards and require immediate response. |
| Unauthorized Intervention | CRITICAL SAFETY NOTICE | CRITICAL | The policy says anyone interacting with equipment without the green vest must be assumed unauthorized. |
| Opened Panel Cover | WARNING | LOW by default | State-based unsafe condition; elevated by context if personnel exposure is present. |
| Carrying Overload with Forklift | CRITICAL SAFETY NOTICE | CRITICAL | The block threshold is explicit: three or more blocks triggers immediate alert. |

## Detection Notes And Limitations

The local repository can run in demo mode immediately. The full Kaggle dataset is intended to be processed in Kaggle Notebook because of its size.

`src/detection/kaggle_manifest.py` creates a lightweight `data/manifest.json` from selected Kaggle videos. The manifest-based interface keeps downstream modules independent from the vision model implementation and preserves the required report fields: clip ID, timestamp, rule reference, observed behavior, zone, and confidence.

For a production-grade version, the detection module should be extended with a trained or zero-shot vision model that localizes people, forklift loads, electrical panels, vest colors, and walkway boundaries frame by frame. The downstream modules are model-agnostic and already accept structured detections.

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
