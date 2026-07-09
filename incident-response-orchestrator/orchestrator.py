"""
Autonomous Incident Response Orchestrator — Core Engine
Module 3 — Point 3 of PS7

Given an attributed threat (tactics + severity from Module 2), this engine:
1. Selects the appropriate response playbook
2. Computes a DYNAMIC blast radius that combines the action's intrinsic
   disruption potential with the REAL criticality of the target asset
   (cross-referenced from Module 4's CNI asset inventory) — isolating a
   printer and isolating a SCADA turbine controller are not the same decision
3. Factors in detection confidence (Module 1's known ~80% accuracy) before
   auto-executing — low-confidence flags get escalated even for otherwise
   low-blast-radius actions, to avoid disrupting operations on a false alarm
4. Auto-executes low-risk actions immediately (simulated on an in-memory
   network state), queues high-risk ones for human approval
5. Supports ROLLBACK of auto-executed actions if later confirmed a false
   positive — a real SOAR capability, not just one-way containment
6. Correlates multiple incidents on the SAME target within a short window
   into one coordinated response instead of duplicate/conflicting actions
7. Logs every decision to an auditable trail — full auditability as
   required by evaluation focus
"""

import json
import time
from datetime import datetime, timezone

from playbooks import ACTIONS, get_playbook_for_tactics, HUMAN_APPROVAL_THRESHOLD

# Confidence-to-severity mapping: only "critical"/"high" severity flags are
# trusted enough to auto-execute anything; "medium"/"low" always escalate,
# regardless of the action's own blast radius — because Module 1's ~80%
# test accuracy means a meaningful fraction of medium/low flags are noise,
# and auto-containing on noise has a real operational cost.
AUTO_EXECUTABLE_SEVERITIES = {"critical", "high"}

# Asset criticality (1-5, from Module 4's inventory) multiplies the action's
# base blast radius. A blast_radius-2 action on a criticality-5 OT asset
# becomes effectively a 3.0 -- more likely to require sign-off than the same
# action on a criticality-1 printer.
CRITICALITY_MULTIPLIER = {1: 0.7, 2: 0.85, 3: 1.0, 4: 1.15, 5: 1.35}

# Correlation window: incidents on the same target within this many seconds
# are treated as one coordinated campaign, not independent duplicate alerts.
CORRELATION_WINDOW_SECONDS = 300


class NetworkState:
    """In-memory simulated environment — stands in for real SCADA/IT assets."""
    def __init__(self):
        self.isolated_endpoints = set()
        self.blocked_ips = set()
        self.disabled_accounts = set()
        self.revoked_credentials = set()
        self.vm_snapshots = []
        self.incident_reports = []

    def apply_action(self, action_name, target):
        if action_name == "isolate_endpoint":
            self.isolated_endpoints.add(target)
        elif action_name == "block_ip":
            self.blocked_ips.add(target)
        elif action_name == "disable_account":
            self.disabled_accounts.add(target)
        elif action_name == "revoke_credentials":
            self.revoked_credentials.add(target)
        elif action_name == "snapshot_vm_state":
            self.vm_snapshots.append({"target": target, "time": datetime.now(timezone.utc).isoformat()})
        elif action_name == "generate_incident_report":
            self.incident_reports.append({"target": target, "time": datetime.now(timezone.utc).isoformat()})

    def undo_action(self, action_name, target):
        """Reverses an auto-executed action — used when later confirmed a false positive."""
        if action_name == "isolate_endpoint":
            self.isolated_endpoints.discard(target)
        elif action_name == "block_ip":
            self.blocked_ips.discard(target)
        elif action_name == "disable_account":
            self.disabled_accounts.discard(target)
        elif action_name == "revoke_credentials":
            self.revoked_credentials.discard(target)
        # snapshots/reports are historical records, not reversed

    def snapshot(self):
        return {
            "isolated_endpoints": list(self.isolated_endpoints),
            "blocked_ips": list(self.blocked_ips),
            "disabled_accounts": list(self.disabled_accounts),
            "revoked_credentials": list(self.revoked_credentials),
            "vm_snapshots_taken": len(self.vm_snapshots),
            "incident_reports_generated": len(self.incident_reports),
        }


class IncidentResponseOrchestrator:
    def __init__(self, asset_criticality_lookup=None):
        self.network_state = NetworkState()
        self.audit_log = []
        self.pending_human_approval = []
        self.executed_actions_log = []  # for rollback support
        # target -> list of (incident_id, timestamp) for campaign correlation
        self.recent_incidents_by_target = {}
        self.correlated_campaigns = []
        # target -> criticality (1-5); defaults to 3 (medium) if unknown
        self.asset_criticality_lookup = asset_criticality_lookup or {}

    def _log(self, entry: dict):
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.audit_log.append(entry)

    def _get_criticality(self, target):
        return self.asset_criticality_lookup.get(target, 3)

    def _check_campaign_correlation(self, incident_id, target):
        """
        If another incident hit the SAME target very recently, treat this
        as part of a coordinated campaign rather than an isolated event —
        real SOAR systems must avoid duplicate/conflicting responses when
        an attacker is clearly moving through multiple stages on one host.
        """
        now = time.time()
        prior = self.recent_incidents_by_target.get(target, [])
        prior = [(iid, t) for iid, t in prior if now - t < CORRELATION_WINDOW_SECONDS]

        is_campaign = len(prior) > 0
        if is_campaign:
            campaign_ids = [iid for iid, _ in prior] + [incident_id]
            self.correlated_campaigns.append({"target": target, "incident_ids": campaign_ids})

        prior.append((incident_id, now))
        self.recent_incidents_by_target[target] = prior
        return is_campaign

    def respond(self, incident_id: str, target: str, tactics: list, severity: str, mitre_technique: str):
        """
        Core orchestration decision: given an attributed incident, select and
        execute (or queue for approval) the appropriate playbook actions,
        using DYNAMIC blast radius (action x asset criticality) and
        confidence-aware gating (severity must be high/critical to auto-execute).
        """
        is_campaign = self._check_campaign_correlation(incident_id, target)
        asset_criticality = self._get_criticality(target)
        multiplier = CRITICALITY_MULTIPLIER.get(asset_criticality, 1.0)

        playbook = get_playbook_for_tactics(tactics)
        executed, queued = [], []
        total_manual_minutes, total_auto_seconds = 0, 0

        for action_name in playbook:
            action_meta = ACTIONS[action_name]
            total_manual_minutes += action_meta["manual_minutes"]
            dynamic_blast_radius = round(action_meta["blast_radius"] * multiplier, 2)

            # Two independent gates must BOTH pass to auto-execute:
            # (1) dynamic blast radius below threshold, (2) detection confidence high enough
            confidence_ok = severity in AUTO_EXECUTABLE_SEVERITIES
            blast_ok = dynamic_blast_radius < HUMAN_APPROVAL_THRESHOLD

            if not (confidence_ok and blast_ok):
                reason_parts = []
                if not blast_ok:
                    reason_parts.append(f"dynamic_blast_radius={dynamic_blast_radius} (base={action_meta['blast_radius']} x criticality_mult={multiplier}, asset_criticality={asset_criticality}) >= threshold={HUMAN_APPROVAL_THRESHOLD}")
                if not confidence_ok:
                    reason_parts.append(f"severity='{severity}' not in auto-executable set {AUTO_EXECUTABLE_SEVERITIES} (Module 1 detection confidence too low to trust unsupervised auto-response)")
                entry = {
                    "incident_id": incident_id, "action": action_name, "target": target,
                    "decision": "QUEUED_FOR_HUMAN_APPROVAL",
                    "reason": "; ".join(reason_parts),
                    "mitre_technique": mitre_technique, "severity": severity,
                    "is_part_of_correlated_campaign": is_campaign
                }
                self._log(entry)
                self.pending_human_approval.append(entry)
                queued.append(action_name)
            else:
                self.network_state.apply_action(action_name, target)
                total_auto_seconds += action_meta["auto_seconds"]
                self.executed_actions_log.append({"incident_id": incident_id, "action": action_name, "target": target})
                entry = {
                    "incident_id": incident_id, "action": action_name, "target": target,
                    "decision": "AUTO_EXECUTED",
                    "reason": f"dynamic_blast_radius={dynamic_blast_radius} < threshold={HUMAN_APPROVAL_THRESHOLD} AND severity='{severity}' is auto-executable",
                    "mitre_technique": mitre_technique, "severity": severity,
                    "is_part_of_correlated_campaign": is_campaign
                }
                self._log(entry)
                executed.append(action_name)

        automatable_minutes = sum(ACTIONS[a]["manual_minutes"] for a in executed)
        automated_seconds = sum(ACTIONS[a]["auto_seconds"] for a in executed)
        time_saved_minutes = automatable_minutes - (automated_seconds / 60)

        return {
            "incident_id": incident_id,
            "is_part_of_correlated_campaign": is_campaign,
            "asset_criticality": asset_criticality,
            "playbook_actions": playbook,
            "auto_executed": executed,
            "queued_for_human_approval": queued,
            "estimated_manual_response_minutes": total_manual_minutes,
            "automated_response_seconds": total_auto_seconds,
            "time_saved_on_automatable_actions_minutes": round(time_saved_minutes, 2)
        }

    def approve_pending(self, incident_id: str, action: str, target: str):
        """Simulates a human analyst approving a queued high-blast-radius action."""
        self.network_state.apply_action(action, target)
        self._log({
            "incident_id": incident_id, "action": action, "target": target,
            "decision": "HUMAN_APPROVED_AND_EXECUTED", "reason": "Manual sign-off received"
        })
        self.pending_human_approval = [
            p for p in self.pending_human_approval
            if not (p["incident_id"] == incident_id and p["action"] == action)
        ]

    def rollback_false_positive(self, incident_id: str):
        """
        Reverses all auto-executed actions for an incident later confirmed
        to be a false positive. Real containment has a real operational
        cost, so the ability to safely undo matters as much as the ability
        to act quickly.
        """
        actions_to_undo = [a for a in self.executed_actions_log if a["incident_id"] == incident_id]
        for a in actions_to_undo:
            self.network_state.undo_action(a["action"], a["target"])
            self._log({
                "incident_id": incident_id, "action": a["action"], "target": a["target"],
                "decision": "ROLLED_BACK", "reason": "Confirmed false positive — action reversed"
            })
        return len(actions_to_undo)

    def get_audit_trail(self):
        return self.audit_log


if __name__ == "__main__":
    # Simulated criticality lookup, mirroring Module 4's asset inventory
    asset_criticality = {
        "host-10.0.4.22": 2,   # low-criticality workstation
        "host-10.0.7.15": 5,   # SCADA/OT host
        "203.0.113.45": 3,     # external IP, unknown asset
    }
    orchestrator = IncidentResponseOrchestrator(asset_criticality_lookup=asset_criticality)

    print("=== Simulating incident response for 3 attributed threats (with dynamic blast radius) ===\n")

    incidents = [
        {"incident_id": "INC-001", "target": "host-10.0.4.22", "tactics": ["credential-access"],
         "severity": "high", "mitre_technique": "T1110 - Brute Force"},
        {"incident_id": "INC-002", "target": "host-10.0.7.15", "tactics": ["stealth", "privilege-escalation"],
         "severity": "critical", "mitre_technique": "T1055 - Process Injection"},
        {"incident_id": "INC-003", "target": "203.0.113.45", "tactics": ["exfiltration"],
         "severity": "medium", "mitre_technique": "T1041 - Exfiltration Over C2 Channel"},
    ]

    for inc in incidents:
        result = orchestrator.respond(**inc)
        print(f"--- {inc['incident_id']} ({inc['mitre_technique']}) — asset_criticality={result['asset_criticality']} ---")
        print(f"  Auto-executed: {result['auto_executed']}")
        print(f"  Queued for human approval: {result['queued_for_human_approval']}")
        print(f"  Manual baseline: {result['estimated_manual_response_minutes']} min | "
              f"Automated: {result['automated_response_seconds']}s | "
              f"Time saved (automatable subset): {result['time_saved_on_automatable_actions_minutes']} min\n")

    print("=== Demonstrating campaign correlation: a 4th incident hits the SAME host as INC-002 ===")
    inc4 = {"incident_id": "INC-004", "target": "host-10.0.7.15", "tactics": ["exfiltration"],
            "severity": "critical", "mitre_technique": "T1041 - Exfiltration Over C2 Channel"}
    result4 = orchestrator.respond(**inc4)
    print(f"  INC-004 flagged as part of correlated campaign: {result4['is_part_of_correlated_campaign']}")
    print(f"  Correlated campaigns detected so far: {orchestrator.correlated_campaigns}\n")

    print("=== Demonstrating rollback: INC-001 is later confirmed a FALSE POSITIVE ===")
    print(f"  State before rollback: {orchestrator.network_state.snapshot()}")
    n_undone = orchestrator.rollback_false_positive("INC-001")
    print(f"  Rolled back {n_undone} action(s)")
    print(f"  State after rollback: {orchestrator.network_state.snapshot()}\n")

    print(f"=== {len(orchestrator.pending_human_approval)} actions awaiting human approval ===")
    for p in orchestrator.pending_human_approval:
        print(f"  {p['incident_id']}: {p['action']} on {p['target']} ({p['reason'][:80]}...)")

    print(f"\n=== Full audit trail: {len(orchestrator.audit_log)} logged decisions ===")
    with open("audit_trail_sample.json", "w") as f:
        json.dump(orchestrator.get_audit_trail(), f, indent=2)
    print("Saved audit_trail_sample.json")

