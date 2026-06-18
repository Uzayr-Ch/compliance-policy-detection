"""
Factory EHS Compliance Operations Room — Streamlit Dashboard.

Features:
    - Live incident monitor with flashing strobe alerts and auditory siren
    - KPI metrics with severity distribution pie/bar charts
    - Chronological alert timeline with colour-coded severity badges
    - SHA-256 audit trail integrity verification panel
    - Historical log browser with multi-filter and CSV/JSON export
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Ensure project root is in python path to handle direct script execution
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st

from src.escalation.router import alert_required
from src.policy.parser import load_rules, write_rules_json
from src.reports.store import CSV_PATH, JSONL_PATH, load_events, verify_audit_trail
from src.run_pipeline import run_pipeline


ROOT = Path(__file__).resolve().parents[2]

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Factory EHS Compliance Operations Room",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Premium dark-theme CSS ───────────────────────────────────────────────────
st.markdown(
    """
<style>
/* ── Import professional font ─────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

/* ── Global overrides ─────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* ── Strobe animations ────────────────────────────────────────── */
@keyframes flash-critical {
    0%   { background: linear-gradient(135deg, #dc2626, #991b1b); box-shadow: 0 0 30px rgba(220,38,38,.6); }
    50%  { background: linear-gradient(135deg, #7f1d1d, #450a0a); box-shadow: 0 0 5px  rgba(220,38,38,.1); }
    100% { background: linear-gradient(135deg, #dc2626, #991b1b); box-shadow: 0 0 30px rgba(220,38,38,.6); }
}
@keyframes flash-high {
    0%   { background: linear-gradient(135deg, #ea580c, #c2410c); box-shadow: 0 0 25px rgba(234,88,12,.5); }
    50%  { background: linear-gradient(135deg, #7c2d12, #431407); box-shadow: 0 0 5px  rgba(234,88,12,.1); }
    100% { background: linear-gradient(135deg, #ea580c, #c2410c); box-shadow: 0 0 25px rgba(234,88,12,.5); }
}

/* ── Alert banners ────────────────────────────────────────────── */
.strobe-critical {
    animation: flash-critical .9s ease-in-out infinite;
    padding: 18px 24px;
    border-radius: 10px;
    color: #fff;
    font-weight: 700;
    text-align: center;
    font-size: 1.15rem;
    margin-bottom: 24px;
    letter-spacing: .6px;
    border: 1px solid rgba(255,255,255,.15);
}
.strobe-high {
    animation: flash-high 1.2s ease-in-out infinite;
    padding: 18px 24px;
    border-radius: 10px;
    color: #fff;
    font-weight: 700;
    text-align: center;
    font-size: 1.15rem;
    margin-bottom: 24px;
    letter-spacing: .6px;
    border: 1px solid rgba(255,255,255,.15);
}

/* ── Status banner ────────────────────────────────────────────── */
.status-ok {
    background: linear-gradient(135deg, #065f46, #047857);
    color: #d1fae5;
    padding: 14px 20px;
    border-radius: 8px;
    font-weight: 600;
    display: inline-block;
    margin-bottom: 16px;
    border: 1px solid rgba(255,255,255,.1);
}

/* ── KPI cards ────────────────────────────────────────────────── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
}
.kpi-card {
    background: linear-gradient(145deg, #1e293b, #0f172a);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 24px 16px;
    text-align: center;
    transition: transform .2s, box-shadow .2s;
}
.kpi-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 25px rgba(0,0,0,.4);
}
.kpi-icon  { font-size: 1.8rem; margin-bottom: 6px; }
.kpi-value { font-size: 2.4rem; font-weight: 800; line-height: 1.1; }
.kpi-label { font-size: .82rem; color: #94a3b8; margin-top: 4px; letter-spacing: .4px; text-transform: uppercase; }

/* severity colours */
.kpi-total    .kpi-value { color: #60a5fa; }
.kpi-critical .kpi-value { color: #f87171; }
.kpi-high     .kpi-value { color: #fb923c; }
.kpi-safe     .kpi-value { color: #4ade80; }

/* ── Severity badges (used in timeline) ───────────────────────── */
.severity-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: .78rem;
    font-weight: 700;
    letter-spacing: .4px;
    text-transform: uppercase;
}
.badge-critical { background: #dc2626; color: #fff; }
.badge-high     { background: #ea580c; color: #fff; }
.badge-medium   { background: #ca8a04; color: #fff; }
.badge-low      { background: #16a34a; color: #fff; }

/* ── Audit trail ──────────────────────────────────────────────── */
.audit-pass {
    background: linear-gradient(135deg, #065f46, #047857);
    padding: 16px 20px;
    border-radius: 10px;
    color: #d1fae5;
    font-weight: 700;
    text-align: center;
    font-size: 1.05rem;
    margin: 12px 0 20px 0;
    border: 1px solid rgba(255,255,255,.1);
}
.audit-fail {
    background: linear-gradient(135deg, #991b1b, #dc2626);
    padding: 16px 20px;
    border-radius: 10px;
    color: #fff;
    font-weight: 700;
    text-align: center;
    font-size: 1.05rem;
    margin: 12px 0 20px 0;
    border: 1px solid rgba(255,255,255,.15);
}

/* ── Section headers ──────────────────────────────────────────── */
.section-header {
    font-size: 1.3rem;
    font-weight: 700;
    color: #e2e8f0;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 2px solid #334155;
}

/* ── Incident card ────────────────────────────────────────────── */
.incident-card {
    background: linear-gradient(145deg, #1e293b, #0f172a);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px;
}
.incident-field { margin-bottom: 10px; }
.incident-label { color: #94a3b8; font-size: .78rem; text-transform: uppercase; letter-spacing: .5px; font-weight: 600; }
.incident-value { color: #e2e8f0; font-size: 1.05rem; font-weight: 600; margin-top: 2px; }
</style>
""",
    unsafe_allow_html=True,
)


# ── Helper functions ─────────────────────────────────────────────────────────

def events_frame() -> pd.DataFrame:
    rows = load_events()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def severity_badge(sev: str) -> str:
    cls = f"badge-{sev.lower()}"
    return f'<span class="severity-badge {cls}">{sev}</span>'


def filtered_frame(df: pd.DataFrame, key_suffix: str = "") -> pd.DataFrame:
    if df.empty:
        return df
    col1, col2, col3 = st.columns(3)
    with col1:
        severities = st.multiselect(
            "Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            default=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            key=f"sev_{key_suffix}",
        )
    with col2:
        classes = sorted(df["behavior_class"].dropna().unique().tolist())
        selected_classes = st.multiselect("Behavior Class", classes, default=classes, key=f"cls_{key_suffix}")
    with col3:
        zones = sorted(df["zone"].dropna().unique().tolist())
        selected_zones = st.multiselect("Zone", zones, default=zones, key=f"zone_{key_suffix}")
    return df[
        df["severity"].isin(severities)
        & df["behavior_class"].isin(selected_classes)
        & df["zone"].isin(selected_zones)
    ]


# ── Page header ──────────────────────────────────────────────────────────────
st.markdown("# 🏭 Factory Compliance & Alert Escalation Control Center")
st.caption("Real-time EHS violation monitoring · Cryptographic audit trail · Automated escalation dispatch")

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Pipeline Operations")
    st.markdown("---")

    if st.button("📄 Extract Policy Rules", use_container_width=True):
        with st.spinner("Parsing compliance_policy.pdf …"):
            rules = write_rules_json()
        st.success(f"Extracted {len(rules)} rules from compliance PDF.")

    if st.button("🧪 Run Demo Pipeline", use_container_width=True):
        with st.spinner("Generating synthetic compliance events …"):
            events = run_pipeline(demo=True)
        st.success(f"Generated {len(events)} demo event(s).")

    if st.button("🎥 Process Video Clips", use_container_width=True):
        with st.spinner("Processing input clips …"):
            events = run_pipeline(demo=False)
        st.success(f"Processed clips → {len(events)} event(s).")

    st.markdown("---")
    st.markdown("### 📋 Active Policy Rules")
    for rule in load_rules():
        with st.expander(f"{rule.policy_rule_ref} — {rule.unsafe_behavior}"):
            st.markdown(f"**Domain:** {rule.domain}")
            st.markdown(f"**Hazard Signal:** `{rule.hazard_signal}`")
            st.markdown(f"**Default Severity:** `{rule.default_severity}`")
            st.markdown(f"**Indicator:** {rule.observable_indicator}")

# ── Load data ────────────────────────────────────────────────────────────────
df = events_frame()

# ── Global strobe alert ──────────────────────────────────────────────────────
if not df.empty:
    latest = df.iloc[0].to_dict()
    severity = latest["severity"]
    if alert_required(severity):
        strobe_class = "strobe-critical" if severity == "CRITICAL" else "strobe-high"
        msg = (
            f"⚠️ {severity} ALERT — {latest['behavior_class']} "
            f"in {latest['zone']} · Ref {latest['policy_rule_ref']}"
        )
        st.markdown(f'<div class="{strobe_class}">{msg}</div>', unsafe_allow_html=True)

        # Browser-native audio siren (Web Audio API)
        st.components.v1.html(
            """
            <script>
            try {
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.connect(gain); gain.connect(ctx.destination);
                osc.type = 'sawtooth';
                const t = ctx.currentTime;
                osc.frequency.setValueAtTime(440, t);
                osc.frequency.linearRampToValueAtTime(880, t + .35);
                osc.frequency.linearRampToValueAtTime(440, t + .7);
                gain.gain.setValueAtTime(.08, t);
                gain.gain.linearRampToValueAtTime(.005, t + .7);
                osc.start(t); osc.stop(t + .7);
            } catch(e) {}
            </script>
            """,
            height=0,
            width=0,
        )

def get_web_compatible_video(video_path: Path) -> Path:
    """
    Ensure the video is in a web-compatible format (H.264).
    If not already transcoded, transcode it using ffmpeg.
    """
    if video_path.name.startswith("web_"):
        return video_path
        
    web_path = video_path.parent / f"web_{video_path.name}"
    if web_path.exists():
        return web_path
        
    try:
        cmd = [
            "ffmpeg", "-y",
            "-i", str(video_path),
            "-vcodec", "libx264",
            "-pix_fmt", "yuv420p",
            "-profile:v", "baseline",
            "-level", "3.0",
            str(web_path)
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return web_path
    except Exception:
        return video_path

# ── Tab layout ───────────────────────────────────────────────────────────────
tab_live, tab_kpi, tab_timeline, tab_audit, tab_history = st.tabs([
    "📺 Live Monitor",
    "📊 Analytics",
    "🕒 Alert Timeline",
    "🛡️ Audit Integrity",
    "🗄️ Historical Logs",
])

# ── Tab 1: Live Monitor ─────────────────────────────────────────────────────
with tab_live:
    if df.empty:
        st.markdown(
            '<div class="status-ok">✔ SYSTEM SECURE — No active violations detected</div>',
            unsafe_allow_html=True,
        )
        st.info("Click **🧪 Run Demo Pipeline** in the sidebar to generate sample events.")
    else:
        left, right = st.columns([3, 2])
        with left:
            st.markdown('<div class="section-header">📹 Incident Video Feed</div>', unsafe_allow_html=True)
            annotated_dir = ROOT / "outputs" / "annotated"
            video_files = list(annotated_dir.glob("*.mp4")) if annotated_dir.exists() else []
            raw_videos = [f for f in video_files if not f.name.startswith("web_")]

            if raw_videos:
                to_transcode = [f for f in raw_videos if not (f.parent / f"web_{f.name}").exists()]
                if to_transcode:
                    with st.spinner("Optimizing video codec for browser playback..."):
                        web_videos = [get_web_compatible_video(f) for f in raw_videos]
                else:
                    web_videos = [f.parent / f"web_{f.name}" for f in raw_videos]
                
                video_map = {f.name.replace("web_", ""): f for f in web_videos}
                sel = st.selectbox("Select annotated clip:", list(video_map.keys()))
                try:
                    with open(video_map[sel], "rb") as vf:
                        st.video(vf.read())
                except Exception as ve:
                    st.error(f"Failed to play video: {ve}")
            else:
                source = latest.get("source_video")
                if source and Path(source).exists():
                    web_source = get_web_compatible_video(Path(source))
                    try:
                        with open(web_source, "rb") as vf:
                            st.video(vf.read())
                    except Exception as ve:
                        st.error(f"Failed to play video: {ve}")
                else:
                    st.info(
                        f"No video feed available.  \n"
                        f"**Clip:** `{latest['clip_id']}` · **Zone:** `{latest['zone']}`"
                    )

        with right:
            st.markdown('<div class="section-header">📋 Incident Dossier</div>', unsafe_allow_html=True)
            st.markdown(
                f"""
<div class="incident-card">
  <div class="incident-field">
    <div class="incident-label">Behavior Class</div>
    <div class="incident-value">{latest["behavior_class"]}</div>
  </div>
  <div class="incident-field">
    <div class="incident-label">Severity</div>
    <div class="incident-value">{severity_badge(latest["severity"])}</div>
  </div>
  <div class="incident-field">
    <div class="incident-label">Confidence</div>
    <div class="incident-value">{latest["confidence"]:.1%}</div>
  </div>
  <div class="incident-field">
    <div class="incident-label">Policy Reference</div>
    <div class="incident-value">{latest["policy_rule_ref"]}</div>
  </div>
  <div class="incident-field">
    <div class="incident-label">Escalation Action</div>
    <div class="incident-value" style="font-size:.92rem;">{latest["escalation_action"]}</div>
  </div>
</div>
""",
                unsafe_allow_html=True,
            )
            with st.expander("Full description"):
                st.write(latest["event_description"])

# ── Tab 2: Analytics ─────────────────────────────────────────────────────────
with tab_kpi:
    if df.empty:
        st.info("No data available. Run the pipeline first.")
    else:
        total = len(df)
        crit = len(df[df["severity"] == "CRITICAL"])
        high = len(df[df["severity"] == "HIGH"])
        safe = total - crit - high

        st.markdown(
            f"""
<div class="kpi-grid">
  <div class="kpi-card kpi-total">
    <div class="kpi-icon">📊</div>
    <div class="kpi-value">{total}</div>
    <div class="kpi-label">Total Events</div>
  </div>
  <div class="kpi-card kpi-critical">
    <div class="kpi-icon">🔴</div>
    <div class="kpi-value">{crit}</div>
    <div class="kpi-label">Critical</div>
  </div>
  <div class="kpi-card kpi-high">
    <div class="kpi-icon">🟠</div>
    <div class="kpi-value">{high}</div>
    <div class="kpi-label">High</div>
  </div>
  <div class="kpi-card kpi-safe">
    <div class="kpi-icon">🟢</div>
    <div class="kpi-value">{safe}</div>
    <div class="kpi-label">Medium / Low</div>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### Violations by Behavior Class")
            st.bar_chart(df["behavior_class"].value_counts())
        with c2:
            st.markdown("#### Severity Distribution")
            sev_counts = df["severity"].value_counts()
            # Use native Streamlit bar_chart for severity distribution
            st.bar_chart(sev_counts)

# ── Tab 3: Alert Timeline ───────────────────────────────────────────────────
with tab_timeline:
    if df.empty:
        st.info("No events recorded yet.")
    else:
        st.markdown('<div class="section-header">Chronological Dispatch Log</div>', unsafe_allow_html=True)
        display_cols = [
            "timestamp", "severity", "behavior_class",
            "zone", "clip_id", "escalation_action",
        ]
        st.dataframe(
            df[display_cols],
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "severity": st.column_config.TextColumn("Severity", width="small"),
                "behavior_class": st.column_config.TextColumn("Violation", width="large"),
                "zone": st.column_config.TextColumn("Zone", width="small"),
                "clip_id": st.column_config.TextColumn("Clip ID", width="medium"),
                "escalation_action": st.column_config.TextColumn("Dispatch Action", width="large"),
            },
        )

# ── Tab 4: Audit Integrity ──────────────────────────────────────────────────
with tab_audit:
    st.markdown('<div class="section-header">🛡️ SHA-256 Audit Trail Verification</div>', unsafe_allow_html=True)
    st.markdown(
        "Every compliance event is cryptographically signed at creation time. "
        "This panel **recalculates** each signature and compares it against "
        "the stored value to detect any post-hoc tampering of safety records."
    )

    if df.empty:
        st.info("No audit records to verify.")
    else:
        reports = verify_audit_trail()
        r_df = pd.DataFrame(reports)
        tampered = int((r_df["verified"] == False).sum())

        if tampered == 0:
            st.markdown(
                f'<div class="audit-pass">✅ INTEGRITY VERIFIED — All {len(r_df)} records pass cryptographic validation</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div class="audit-fail">🚨 TAMPER DETECTED — {tampered} of {len(r_df)} records fail SHA-256 verification</div>',
                unsafe_allow_html=True,
            )

        st.dataframe(
            r_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "event_id": st.column_config.TextColumn("Event ID", width="large"),
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "behavior_class": st.column_config.TextColumn("Violation", width="large"),
                "signature": st.column_config.TextColumn("SHA-256 Signature", width="large"),
                "verified": st.column_config.CheckboxColumn("Verified", width="small"),
            },
        )

# ── Tab 5: Historical Logs ──────────────────────────────────────────────────
with tab_history:
    if df.empty:
        st.info("Historical database is empty.")
    else:
        st.markdown('<div class="section-header">Historical Log Query & Export</div>', unsafe_allow_html=True)
        filtered = filtered_frame(df, key_suffix="hist")
        st.dataframe(filtered, use_container_width=True, hide_index=True)

        csv_bytes = filtered.to_csv(index=False).encode("utf-8")
        json_bytes = json.dumps(filtered.to_dict(orient="records"), indent=2).encode("utf-8")

        c1, c2 = st.columns(2)
        with c1:
            st.download_button(
                "📥 Export CSV", csv_bytes,
                file_name="compliance_events.csv", mime="text/csv",
                use_container_width=True,
            )
        with c2:
            st.download_button(
                "📥 Export JSON", json_bytes,
                file_name="compliance_events.json", mime="application/json",
                use_container_width=True,
            )
        st.caption(
            f"Persistent stores: `{CSV_PATH.relative_to(ROOT)}` · "
            f"`{JSONL_PATH.relative_to(ROOT)}`"
        )
