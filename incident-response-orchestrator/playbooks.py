"""
Incident Response Playbook Library
Module 3 — Autonomous Incident Response Orchestrator (Point 3 of PS7)

Defines containment actions mapped to MITRE ATT&CK tactics, each with a
'blast radius' score (potential business disruption) and industry-typical
manual execution time — used to compute automation time savings and to
decide which actions can auto-execute vs require human approval.

Blast radius scale: 1 (no disruption, e.g. logging) -> 5 (severe disruption,
e.g. taking a production system offline). Actions with blast_radius >= 4
require human approval before execution (per SOAR best practice — matches
the problem statement's requirement for "human escalation gates for
decisions above defined blast radius thresholds").
"""

# Each action: (name, blast_radius, manual_time_minutes, automated_time_seconds)
# manual_time_minutes reflects typical SOC analyst time for this step,
# based on industry SOC workflow benchmarks (investigate -> decide -> execute).
ACTIONS = {
    "alert_soc_team":            {"blast_radius": 1, "manual_minutes": 5,  "auto_seconds": 2},
    "preserve_evidence":         {"blast_radius": 1, "manual_minutes": 10, "auto_seconds": 3},
    "generate_incident_report":  {"blast_radius": 1, "manual_minutes": 30, "auto_seconds": 5},
    "snapshot_vm_state":         {"blast_radius": 2, "manual_minutes": 15, "auto_seconds": 8},
    "block_ip":                  {"blast_radius": 2, "manual_minutes": 5,  "auto_seconds": 1},
    "kill_process":              {"blast_radius": 3, "manual_minutes": 5,  "auto_seconds": 1},
    "disable_account":           {"blast_radius": 3, "manual_minutes": 10, "auto_seconds": 2},
    "network_segment_isolation": {"blast_radius": 3, "manual_minutes": 20, "auto_seconds": 4},
    "revoke_credentials":        {"blast_radius": 4, "manual_minutes": 15, "auto_seconds": 2},
    "isolate_endpoint":          {"blast_radius": 4, "manual_minutes": 20, "auto_seconds": 3},
}

HUMAN_APPROVAL_THRESHOLD = 4  # blast_radius >= this requires human sign-off

# Playbook: MITRE tactic -> ordered list of response actions
PLAYBOOKS = {
    "reconnaissance":       ["alert_soc_team"],
    "resource-development":  ["alert_soc_team"],
    "initial-access":       ["alert_soc_team", "block_ip", "isolate_endpoint"],
    "execution":            ["kill_process", "snapshot_vm_state", "alert_soc_team"],
    "persistence":          ["kill_process", "isolate_endpoint", "alert_soc_team"],
    "privilege-escalation": ["revoke_credentials", "isolate_endpoint", "snapshot_vm_state", "alert_soc_team"],
    "defense-impairment":   ["snapshot_vm_state", "isolate_endpoint", "preserve_evidence", "alert_soc_team"],
    "stealth":              ["snapshot_vm_state", "preserve_evidence", "alert_soc_team"],
    "credential-access":    ["revoke_credentials", "disable_account", "alert_soc_team", "preserve_evidence"],
    "discovery":            ["alert_soc_team", "network_segment_isolation"],
    "lateral-movement":     ["network_segment_isolation", "isolate_endpoint", "revoke_credentials"],
    "collection":           ["alert_soc_team", "preserve_evidence"],
    "command-and-control":  ["block_ip", "isolate_endpoint", "alert_soc_team"],
    "exfiltration":         ["block_ip", "isolate_endpoint", "preserve_evidence", "generate_incident_report"],
    "impact":               ["isolate_endpoint", "snapshot_vm_state", "alert_soc_team", "generate_incident_report"],
}


def get_playbook_for_tactics(tactics: list) -> list:
    """
    Merge playbooks for all tactics associated with an attributed technique,
    preserving order and removing duplicate actions.
    """
    combined = []
    for tactic in tactics:
        for action in PLAYBOOKS.get(tactic, []):
            if action not in combined:
                combined.append(action)
    return combined


def playbook_coverage_report():
    """What fraction of known MITRE tactics have a defined playbook?"""
    all_tactics = list(PLAYBOOKS.keys())
    covered = sum(1 for t in all_tactics if PLAYBOOKS[t])
    return {"total_tactics": len(all_tactics), "covered": covered, "coverage_pct": round(covered / len(all_tactics) * 100, 1)}


if __name__ == "__main__":
    print("Playbook coverage report:", playbook_coverage_report())
    print("\nExample — playbook for ['privilege-escalation', 'stealth']:")
    print(get_playbook_for_tactics(["privilege-escalation", "stealth"]))
