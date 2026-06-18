from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.escalation.router import alert_required
from src.policy.parser import load_rules, write_rules_json
from src.reports.store import CSV_PATH, JSONL_PATH, load_events
from src.run_pipeline import run_pipeline


ROOT = Path(__file__).resolve().parents[2]


st.set_page_config(page_title="Factory Compliance Ops", layout="wide")

st.markdown(
    """
    <style>
    .alert-critical {background:#b42318;color:white;padding:14px 16px;border-radius:6px;font-weight:700;}
    .alert-high {background:#f79009;color:#111;padding:14px 16px;border-radius:6px;font-weight:700;}
    .status-ok {color:#067647;font-weight:700;}
    .metric-box {border:1px solid #ddd;padding:10px;border-radius:6px;}
    </style>
    """,
    unsafe_allow_html=True,
)


def events_frame() -> pd.DataFrame:
    rows = load_events()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def filtered_frame(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    col1, col2, col3 = st.columns(3)
    with col1:
        severities = st.multiselect(
            "Severity",
            ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            default=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        )
    with col2:
        classes = sorted(df["behavior_class"].dropna().unique().tolist())
        selected_classes = st.multiselect("Behavior class", classes, default=classes)
    with col3:
        zones = sorted(df["zone"].dropna().unique().tolist())
        selected_zones = st.multiselect("Zone", zones, default=zones)
    filtered = df[
        df["severity"].isin(severities)
        & df["behavior_class"].isin(selected_classes)
        & df["zone"].isin(selected_zones)
    ]
    return filtered


st.title("Factory Compliance & Alert Escalation")

with st.sidebar:
    st.header("Pipeline")
    if st.button("Extract policy rules", use_container_width=True):
        rules = write_rules_json()
        st.success(f"Extracted {len(rules)} rules from the policy PDF.")
    if st.button("Run demo pipeline", use_container_width=True):
        events = run_pipeline(demo=True)
        st.success(f"Generated {len(events)} event(s).")
    if st.button("Process data/ clips", use_container_width=True):
        events = run_pipeline(demo=False)
        st.success(f"Generated {len(events)} event(s).")

    st.header("Rules")
    for rule in load_rules():
        st.caption(f"{rule.policy_rule_ref} | {rule.default_severity}")
        st.write(rule.unsafe_behavior)

df = events_frame()

tab_live, tab_timeline, tab_history = st.tabs(
    ["Live Feed Monitor", "Alert Timeline Stream", "Historical Log & Export"]
)

with tab_live:
    if df.empty:
        st.markdown('<span class="status-ok">No violation detected</span>', unsafe_allow_html=True)
        st.info("Run the demo pipeline or place videos in data/ and process clips.")
    else:
        latest = df.iloc[0].to_dict()
        severity = latest["severity"]
        if alert_required(severity):
            css_class = "alert-critical" if severity == "CRITICAL" else "alert-high"
            st.markdown(
                f'<div class="{css_class}">{severity} ALERT: {latest["behavior_class"]}</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(f"Status: violation detected ({severity})")

        left, right = st.columns([2, 1])
        with left:
            source = latest.get("source_video")
            if source and Path(source).exists():
                st.video(source)
            else:
                st.empty().container().info(
                    f"Simulated feed for {latest['clip_id']} at {latest['zone']}."
                )
        with right:
            st.metric("Severity", severity)
            st.metric("Confidence", f"{latest['confidence']:.0%}")
            st.write(latest["event_description"])

with tab_timeline:
    if df.empty:
        st.info("No events have been generated yet.")
    else:
        st.dataframe(
            df[
                [
                    "timestamp",
                    "severity",
                    "behavior_class",
                    "zone",
                    "clip_id",
                    "escalation_action",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

with tab_history:
    if df.empty:
        st.info("Historical log is empty.")
    else:
        filtered = filtered_frame(df)
        st.dataframe(filtered, use_container_width=True, hide_index=True)
        csv_bytes = filtered.to_csv(index=False).encode("utf-8")
        json_bytes = json.dumps(filtered.to_dict(orient="records"), indent=2).encode("utf-8")
        c1, c2 = st.columns(2)
        with c1:
            st.download_button(
                "Export CSV",
                csv_bytes,
                file_name="filtered_compliance_log.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with c2:
            st.download_button(
                "Export JSON",
                json_bytes,
                file_name="filtered_compliance_log.json",
                mime="application/json",
                use_container_width=True,
            )
        st.caption(f"Append-only files: {CSV_PATH.relative_to(ROOT)} and {JSONL_PATH.relative_to(ROOT)}")
