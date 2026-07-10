"""
Cyber Sentinel CNI — Unified Dashboard
Ties together all 5 modules into one interactive Streamlit app.

Run with: streamlit run app.py
"""

import sys
import os
import json
import joblib
import pandas as pd
import streamlit as st

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)

sys.path.append(os.path.join(ROOT, "anomaly-detection"))
sys.path.append(os.path.join(ROOT, "attribution-agent"))
sys.path.append(os.path.join(ROOT, "incident-response-orchestrator"))
sys.path.append(os.path.join(ROOT, "vulnerability-prioritization"))
sys.path.append(os.path.join(ROOT, "digital-twin"))

st.set_page_config(page_title="Cyber Sentinel CNI", layout="wide", page_icon="🛡️")


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


# ============================================================
# HEADER
# ============================================================
st.title("🛡️ Cyber Sentinel CNI")
st.caption("AI-Driven Cyber Resilience for Critical National Infrastructure — ET AI Hackathon 2026, Problem Statement 7")

tabs = st.tabs([
    "🏠 Overview",
    "1️⃣ Anomaly Detection",
    "2️⃣ APT Attribution",
    "3️⃣ Incident Response",
    "4️⃣ Vulnerability Priority",
    "5️⃣ Digital Twin"
])

# ============================================================
# TAB 0 — OVERVIEW
# ============================================================
with tabs[0]:
    st.header("Platform Overview")
    st.markdown("""
    A behavioural intelligence platform that detects cyber threats to critical infrastructure
    **without relying on known malware signatures** — and responds to them automatically where it's safe to.
    """)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Anomaly Detection F1", "0.874", "ensemble model")
    col2.metric("Attribution Top-3 Acc.", "96.0%", "697 MITRE techniques")
    col3.metric("Auto-Response Rate", "77.5%", "22.5% escalated")
    col4.metric("CVEs Analyzed", "120,875", "real NVD data")
    col5.metric("Compliance", "100%", "0 violations")

    st.divider()
    st.subheader("How it fits together")
    st.markdown("""
    1. **Module 1** flags anomalous network behaviour in real time
    2. **Module 2** maps that behaviour to a MITRE ATT&CK technique and predicts what's next
    3. **Module 3** automatically contains low-risk threats, escalates high-risk ones to a human
    4. **Module 4** tells you which vulnerabilities to patch first, given what's actively being targeted
    5. **Module 5** simulates attack paths through your infrastructure and tests what security investments actually help
    """)
    st.info("Use the tabs above to explore each module — most support live interaction, not just static results.")

# ============================================================
# TAB 1 — ANOMALY DETECTION
# ============================================================
with tabs[1]:
    st.header("Module 1: Behavioural Anomaly Detection Engine")

    summary = load_json(os.path.join(ROOT, "anomaly-detection", "rigorous_evaluation_summary.json"))
    if summary:
        c1, c2, c3 = st.columns(3)
        c1.metric("Ensemble F1", summary["ensemble"]["f1"])
        c2.metric("Ensemble Precision", summary["ensemble"]["precision"])
        c3.metric("Ensemble Recall", summary["ensemble"]["recall"])

    st.subheader("Try it live: score a real network event")
    st.caption("Pulls an actual row from the NSL-KDD test set and scores it with the trained model.")

    attack_type = st.selectbox("Pick an attack category to sample from",
                                ["normal", "neptune (DoS)", "satan (Probe)", "guess_passwd (R2L)", "buffer_overflow (U2R)"])

    if st.button("Score a sample event", key="score_btn"):
        try:
            from preprocess import COLUMN_NAMES, load_data
            from anomaly_model import check_single_event

            model = joblib.load(os.path.join(ROOT, "anomaly-detection", "anomaly_model.pkl"))
            scaler = joblib.load(os.path.join(ROOT, "anomaly-detection", "scaler.pkl"))
            encoders = joblib.load(os.path.join(ROOT, "anomaly-detection", "encoders.pkl"))
            feature_cols = [c for c in COLUMN_NAMES if c not in ("label", "difficulty")]

            train_df, test_df = load_data(
                os.path.join(ROOT, "data", "nsl-kdd", "KDDTrain+.txt"),
                os.path.join(ROOT, "data", "nsl-kdd", "KDDTest+.txt")
            )
            true_label = attack_type.split(" ")[0]
            rows = test_df[test_df["label"] == true_label]
            row = rows.sample(1, random_state=None).iloc[0]
            raw_event = row[feature_cols].to_dict()

            result = check_single_event(model, scaler, encoders, feature_cols, raw_event)

            colA, colB, colC = st.columns(3)
            colA.metric("True label", true_label)
            colB.metric("Anomaly score", result["anomaly_score"])
            colC.metric("Severity", result["severity"].upper())

            if result["is_anomaly"]:
                st.success(f"✅ Flagged as ANOMALOUS (severity: {result['severity']})")
            else:
                st.warning("⚪ Classified as NORMAL behaviour")

        except Exception as e:
            st.error(f"Could not run live scoring: {e}")

    st.divider()
    st.subheader("Evaluation results")
    col1, col2 = st.columns(2)
    with col1:
        st.image(os.path.join(ROOT, "anomaly-detection", "roc_curve_comparison.png"), caption="ROC: Statistical baseline vs Isolation Forest vs Ensemble")
        st.image(os.path.join(ROOT, "anomaly-detection", "detection_rate_by_category.png"), caption="Detection rate by attack category")
    with col2:
        st.image(os.path.join(ROOT, "anomaly-detection", "confusion_matrix.png"), caption="Confusion matrix")
        st.image(os.path.join(ROOT, "anomaly-detection", "feature_importance.png"), caption="Top features driving detection")

    st.warning("**Known limitation:** R2L (8.6%) and U2R (28.4%) detection rates are weak — these attacks are low-volume "
               "and behaviourally subtle, a documented challenge in NSL-KDD research generally. This directly feeds into "
               "Module 5's risk scenarios.")

# ============================================================
# TAB 2 — APT ATTRIBUTION
# ============================================================
with tabs[2]:
    st.header("Module 2: APT Campaign Attribution & Prediction Agent")

    eval_summary = load_json(os.path.join(ROOT, "attribution-agent", "attribution_evaluation_summary.json"))
    if eval_summary:
        c1, c2 = st.columns(2)
        c1.metric("Top-1 retrieval accuracy", f"{eval_summary['retrieval_accuracy']['top1_accuracy']*100:.1f}%")
        c2.metric("Top-3 retrieval accuracy", f"{eval_summary['retrieval_accuracy']['top3_accuracy']*100:.1f}%")

    st.subheader("Try it live: describe observed behaviour")
    default_text = "attacker scanning multiple ports and services across the internal network"
    user_query = st.text_area("Describe the suspicious behaviour observed", value=default_text, height=80)

    if st.button("Attribute to MITRE ATT&CK", key="attribute_btn"):
        try:
            from attribution_agent import AttributionAgent
            if "agent" not in st.session_state:
                with st.spinner("Loading MITRE ATT&CK index (first time only)..."):
                    st.session_state["agent"] = AttributionAgent()
            agent = st.session_state["agent"]

            results = agent.attribute(user_query, top_k=3)
            for r in results:
                with st.container(border=True):
                    st.markdown(f"**{r['mitre_id']} — {r['name']}** (similarity: {r['similarity_score']})")
                    st.caption(f"Tactics: {', '.join(r['tactics'])}")
                    st.caption(f"Known threat groups: {', '.join(r['known_threat_groups'][:3])}")
                    st.caption(f"Predicted next tactics: {', '.join(r['predicted_next_tactics']) if r['predicted_next_tactics'] else 'none'}")
                    st.caption(f"Recommended mitigations: {', '.join(r['recommended_mitigations'][:3])}")
        except Exception as e:
            st.error(f"Could not run attribution: {e}")

    st.divider()
    if eval_summary and "example_campaign_narrative" in eval_summary:
        st.subheader("Example: multi-stage campaign reconstruction")
        narrative = eval_summary["example_campaign_narrative"]["narrative"]
        for step in narrative:
            st.markdown(f"**Step {step['step']}:** {step['attributed_technique']}  \n*{step['observed_behaviour']}*")

        st.subheader("Closest-matching known APT groups")
        groups = eval_summary["example_campaign_narrative"]["most_likely_campaign_match"]
        st.dataframe(pd.DataFrame(groups), use_container_width=True)

# ============================================================
# TAB 3 — INCIDENT RESPONSE
# ============================================================
with tabs[3]:
    st.header("Module 3: Autonomous Incident Response Orchestrator")

    pipeline_summary = load_json(os.path.join(ROOT, "incident-response-orchestrator", "full_pipeline_evaluation_summary.json"))
    if pipeline_summary:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Attacks detected & responded", f"{pipeline_summary['detected_by_module1']}/{pipeline_summary['n_incidents_tested']}")
        c2.metric("Auto-executed", f"{pipeline_summary['auto_executed_pct']}%")
        c3.metric("Escalated to human", f"{pipeline_summary['escalated_pct']}%")
        c4.metric("Compliance violations", pipeline_summary["compliance_audit"]["compliance_violations_found"])

    st.subheader("Try it live: simulate an incident")
    col1, col2, col3 = st.columns(3)
    with col1:
        target = st.selectbox("Target asset", ["PLC-01", "SCADA-01", "WIN-DC-01", "VPN-GW-01", "DB-01", "WEB-01", "PRINT-01"])
    with col2:
        severity = st.selectbox("Detection severity", ["critical", "high", "medium", "low"])
    with col3:
        tactic = st.selectbox("MITRE tactic", ["credential-access", "privilege-escalation", "exfiltration", "lateral-movement", "stealth"])

    if st.button("Run orchestrator decision", key="orch_btn"):
        try:
            from orchestrator import IncidentResponseOrchestrator
            sys.path.append(os.path.join(ROOT, "vulnerability-prioritization"))
            from asset_matcher import ASSET_INVENTORY

            criticality_lookup = {a["asset_id"]: a["criticality"] for a in ASSET_INVENTORY}
            orch = IncidentResponseOrchestrator(asset_criticality_lookup=criticality_lookup)
            result = orch.respond(
                incident_id="DEMO-001", target=target, tactics=[tactic],
                severity=severity, mitre_technique="Demo simulation"
            )

            st.write(f"**Asset criticality:** {result['asset_criticality']}/5")
            colA, colB = st.columns(2)
            with colA:
                st.success(f"**Auto-executed:** {', '.join(result['auto_executed']) if result['auto_executed'] else 'none'}")
            with colB:
                st.warning(f"**Queued for human approval:** {', '.join(result['queued_for_human_approval']) if result['queued_for_human_approval'] else 'none'}")
            st.caption(f"Manual baseline: {result['estimated_manual_response_minutes']} min | "
                       f"Automated: {result['automated_response_seconds']}s | "
                       f"Time saved: {result['time_saved_on_automatable_actions_minutes']} min")
        except Exception as e:
            st.error(f"Could not run orchestrator: {e}")

    st.divider()
    st.subheader("Audit trail sample")
    audit = load_json(os.path.join(ROOT, "incident-response-orchestrator", "audit_trail_sample.json"))
    if audit:
        st.dataframe(pd.DataFrame(audit), use_container_width=True, height=250)

# ============================================================
# TAB 4 — VULNERABILITY PRIORITIZATION
# ============================================================
with tabs[4]:
    st.header("Module 4: Government Infrastructure Vulnerability Prioritisation")

    vuln_summary = load_json(os.path.join(ROOT, "vulnerability-prioritization", "vulnerability_prioritization_summary.json"))
    if vuln_summary:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("CVEs in corpus", f"{vuln_summary['cves_in_corpus']:,}")
        c2.metric("Actively exploited (KEV)", vuln_summary["actively_exploited_kev_count_in_queue"])
        c3.metric("Threat-actor relevant pairs", vuln_summary["threat_actor_relevant_pairs"])
        c4.metric("KEV missed by naive ranking", vuln_summary["kev_missed_by_naive_ranking"])

    st.image(os.path.join(ROOT, "vulnerability-prioritization", "risk_ranking_comparison.png"),
             caption="Contextualized vs naive CVSS-only risk ranking")

    st.subheader("Full remediation queue")
    try:
        queue_df = pd.read_csv(os.path.join(ROOT, "vulnerability-prioritization", "remediation_queue.csv"))
        asset_filter = st.multiselect("Filter by asset", options=sorted(queue_df["asset_id"].unique()))
        display_df = queue_df[queue_df["asset_id"].isin(asset_filter)] if asset_filter else queue_df
        st.dataframe(
            display_df[["asset_id", "cve", "contextualized_risk_score", "naive_cvss_only_score", "cisa_kev", "threat_actor_relevant"]]
            .sort_values("contextualized_risk_score", ascending=False),
            use_container_width=True, height=350
        )
    except FileNotFoundError:
        st.warning("Run Module 4's risk_ranking.py first to generate the remediation queue.")

    if vuln_summary and "capacity_constrained_schedule" in vuln_summary:
        st.subheader("6-week capacity-constrained remediation schedule")
        for week, items in vuln_summary["capacity_constrained_schedule"].items():
            if items:
                with st.expander(week):
                    st.dataframe(pd.DataFrame(items), use_container_width=True)

# ============================================================
# TAB 5 — DIGITAL TWIN
# ============================================================
with tabs[5]:
    st.header("Module 5: Cyber Resilience Digital Twin")

    st.image(os.path.join(ROOT, "digital-twin", "topology_diagram.png"), caption="CNI network topology")

    st.subheader("Security investment impact: before vs after")
    st.image(os.path.join(ROOT, "digital-twin", "scenario_comparison.png"))

    twin_summary = load_json(os.path.join(ROOT, "digital-twin", "digital_twin_scenario_summary.json"))
    if twin_summary:
        for scenario_name, r in twin_summary.items():
            with st.expander(f"{scenario_name} — {r['critical_targets_still_reachable']}/{r['critical_targets_total']} critical assets reachable"):
                for target, path in r["path_details"].items():
                    st.write(f"**{target}:** {' → '.join(path) if path else 'BLOCKED — no path'}")

    st.divider()
    st.subheader("Red-team scenario ranking")
    st.caption("Ranked by expected undetected risk = criticality reachable × (1 − Module 1's real detection probability)")
    red_team = load_json(os.path.join(ROOT, "digital-twin", "red_team_scenario_results.json"))
    if red_team:
        rt_df = pd.DataFrame(red_team)[["scenario", "total_criticality_at_risk", "module1_detection_probability", "expected_undetected_risk"]]
        rt_df = rt_df.sort_values("expected_undetected_risk", ascending=False)
        st.dataframe(rt_df, use_container_width=True)

st.divider()
st.caption("Cyber Sentinel CNI — Raghav Marda, ET AI Hackathon 2026, Problem Statement 7")
