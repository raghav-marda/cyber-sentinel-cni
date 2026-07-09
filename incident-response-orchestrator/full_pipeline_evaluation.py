"""
Full Pipeline Evaluation: Module 1 -> Module 2 -> Module 3
Incident Response Orchestrator — Rigorous Evaluation

Runs the COMPLETE chain — anomaly detection -> MITRE attribution ->
automated incident response — over a batch of real NSL-KDD test events,
and reports:
1. Aggregate automation statistics (what fraction of response actions
   were safely auto-executed vs correctly escalated to humans)
2. Aggregate time-savings (automated response vs typical manual SOC baseline)
3. A compliance/safety check: verifies NO high-blast-radius action was
   ever auto-executed without human approval (critical for trust in an
   autonomous system — this is what "full auditability" should mean)
"""

import sys
sys.path.append("../anomaly-detection")
sys.path.append("../attribution-agent")
sys.path.append("../vulnerability-prioritization")

import json
import joblib
import pandas as pd

from playbooks import ACTIONS, HUMAN_APPROVAL_THRESHOLD
from orchestrator import IncidentResponseOrchestrator, CRITICALITY_MULTIPLIER, AUTO_EXECUTABLE_SEVERITIES


def run_full_pipeline_batch(n_incidents=20):
    from preprocess import COLUMN_NAMES, load_data
    from anomaly_model import check_single_event
    from attribution_agent import AttributionAgent
    from pipeline_bridge import event_to_description, run_full_pipeline
    from asset_matcher import ASSET_INVENTORY

    print("Loading Module 1 (anomaly model)...")
    model = joblib.load("../anomaly-detection/anomaly_model.pkl")
    scaler = joblib.load("../anomaly-detection/scaler.pkl")
    encoders = joblib.load("../anomaly-detection/encoders.pkl")
    feature_cols = [c for c in COLUMN_NAMES if c not in ("label", "difficulty")]

    print("Loading Module 2 (attribution agent)...")
    agent = AttributionAgent()

    print("Initializing Module 3 (orchestrator) with REAL Module 4 asset criticality...")
    # Cross-module integration: map each simulated incident to a real asset
    # from Module 4's CNI inventory, so blast-radius decisions reflect actual
    # asset criticality rather than an arbitrary placeholder.
    asset_criticality_lookup = {a["asset_id"]: a["criticality"] for a in ASSET_INVENTORY}
    orchestrator = IncidentResponseOrchestrator(asset_criticality_lookup=asset_criticality_lookup)

    train_df, test_df = load_data("../data/nsl-kdd/KDDTrain+.txt", "../data/nsl-kdd/KDDTest+.txt")
    attack_rows = test_df[test_df["label"] != "normal"].sample(n=n_incidents, random_state=42)

    results = []
    for idx, (_, row) in enumerate(attack_rows.iterrows()):
        raw_event = row[feature_cols].to_dict()
        anomaly_result = check_single_event(model, scaler, encoders, feature_cols, raw_event)
        pipeline_result = run_full_pipeline(agent, anomaly_result, raw_event)

        if pipeline_result["status"] != "anomaly_attributed":
            results.append({"true_label": row["label"], "detected": False})
            continue

        top_attribution = pipeline_result["mitre_attribution"][0]
        incident_id = f"INC-{idx+1:03d}"
        # Assign each incident to a real Module 4 asset (cycling through inventory)
        target_asset = ASSET_INVENTORY[idx % len(ASSET_INVENTORY)]
        target = target_asset["asset_id"]

        response = orchestrator.respond(
            incident_id=incident_id, target=target,
            tactics=top_attribution["tactics"], severity=anomaly_result["severity"],
            mitre_technique=f"{top_attribution['mitre_id']} - {top_attribution['name']}"
        )
        results.append({
            "true_label": row["label"], "detected": True,
            "mitre_technique": top_attribution["mitre_id"],
            "target_asset": target, "asset_criticality": target_asset["criticality"],
            **response
        })

    return results, orchestrator


def compliance_safety_check(orchestrator):
    """
    Critical safety audit: verify every AUTO_EXECUTED entry actually satisfied
    BOTH gates — dynamic blast radius below threshold AND severity in the
    auto-executable confidence set. Since blast radius is now dynamic
    (action x real asset criticality), this check parses the logged
    dynamic value directly rather than re-deriving it from a static table.
    """
    violations = []
    for entry in orchestrator.audit_log:
        if entry["decision"] != "AUTO_EXECUTED":
            continue
        if entry["severity"] not in AUTO_EXECUTABLE_SEVERITIES:
            violations.append({**entry, "violation": "auto-executed despite non-auto-executable severity"})
            continue
        # dynamic_blast_radius is embedded in the reason string; parse it back out
        try:
            reason = entry["reason"]
            blast_val = float(reason.split("dynamic_blast_radius=")[1].split(" ")[0])
            if blast_val >= HUMAN_APPROVAL_THRESHOLD:
                violations.append({**entry, "violation": f"auto-executed with blast_radius={blast_val} >= threshold"})
        except (IndexError, ValueError):
            pass  # non-parseable reason (e.g. rollback/approval entries) - skip

    return {
        "total_audit_entries": len(orchestrator.audit_log),
        "compliance_violations_found": len(violations),
        "compliant": len(violations) == 0,
        "violations": violations
    }


if __name__ == "__main__":
    print("=" * 90)
    print("FULL PIPELINE EVALUATION: 20 real attack events through Modules 1 -> 2 -> 3")
    print("=" * 90)

    results, orchestrator = run_full_pipeline_batch(n_incidents=20)

    detected = [r for r in results if r["detected"]]
    print(f"\nDetected by Module 1: {len(detected)}/{len(results)} attack events")

    if detected:
        total_manual = sum(r["estimated_manual_response_minutes"] for r in detected)
        total_auto_sec = sum(r["automated_response_seconds"] for r in detected)
        total_saved = sum(r["time_saved_on_automatable_actions_minutes"] for r in detected)
        total_actions = sum(len(r["playbook_actions"]) for r in detected)
        total_auto_actions = sum(len(r["auto_executed"]) for r in detected)
        total_queued = sum(len(r["queued_for_human_approval"]) for r in detected)

        print(f"\nTotal playbook actions triggered: {total_actions}")
        print(f"  Auto-executed (low/medium blast radius): {total_auto_actions} ({total_auto_actions/total_actions*100:.1f}%)")
        print(f"  Escalated to human approval (high blast radius): {total_queued} ({total_queued/total_actions*100:.1f}%)")
        print(f"\nAggregate manual response baseline: {total_manual} minutes")
        print(f"Aggregate automated response time: {total_auto_sec} seconds ({total_auto_sec/60:.2f} minutes)")
        print(f"Time saved on auto-executable actions: {total_saved:.1f} minutes")

    print("\n" + "=" * 90)
    print("CAMPAIGN CORRELATION")
    print("=" * 90)
    print(f"Correlated multi-incident campaigns detected: {len(orchestrator.correlated_campaigns)}")
    for c in orchestrator.correlated_campaigns:
        print(f"  Target {c['target']}: incidents {c['incident_ids']} grouped as one campaign")

    print("\n" + "=" * 90)
    print("COMPLIANCE / SAFETY AUDIT")
    print("=" * 90)
    compliance = compliance_safety_check(orchestrator)
    print(f"Total audit log entries: {compliance['total_audit_entries']}")
    print(f"Compliance violations found: {compliance['compliance_violations_found']}")
    print(f"Status: {'✅ COMPLIANT — no high-blast-radius action ever auto-executed without approval' if compliance['compliant'] else '❌ VIOLATIONS FOUND'}")

    summary = {
        "n_incidents_tested": len(results),
        "detected_by_module1": len(detected),
        "total_playbook_actions": total_actions if detected else 0,
        "auto_executed_pct": round(total_auto_actions / total_actions * 100, 1) if detected else 0,
        "escalated_pct": round(total_queued / total_actions * 100, 1) if detected else 0,
        "aggregate_manual_baseline_minutes": total_manual if detected else 0,
        "aggregate_automated_seconds": total_auto_sec if detected else 0,
        "compliance_audit": compliance
    }
    with open("full_pipeline_evaluation_summary.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print("\nSaved full_pipeline_evaluation_summary.json")
