"""
Autonomous Incident Response Orchestrator — Core Engine
Module 3 — Point 3 of PS7

Given an attributed threat (tactics + severity from Module 2), this engine:
1. Selects the appropriate response playbook
2. Auto-executes low-blast-radius actions immediately (simulated on an
   in-memory network state — endpoints, credentials, IP blocklist)
3. Places high-blast-radius actions into a human-approval queue instead of
   auto-executing them (matches problem statement's escalation-gate requirement)
4. Logs every decision to an auditable trail (timestamp, action, reasoning,
   auto/human-gated) — full auditability as required by evaluation focus
5. Computes time-savings vs a typical manual SOC response
"""

import json
import time
from datetime import datetime, timezone

from playbooks import ACTIONS, get_playbook_for_tactics, HUMAN_APPROVAL_THRESHOLD


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
        # alert_soc_team, preserve_evidence, kill_process, network_segment_isolation:
        # logged only (no persistent state change needed for this simulation)

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
    def __init__(self):
        self.network_state = NetworkState()
        self.audit_log = []
        self.pending_human_approval = []

    def _log(self, entry: dict):
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.audit_log.append(entry)

    def respond(self, incident_id: str, target: str, tactics: list, severity: str, mitre_technique: str):
        """
        Core orchestration decision: given an attributed incident, select and
        execute (or queue for approval) the appropriate playbook actions.
        """
        playbook = get_playbook_for_tactics(tactics)
        executed, queued = [], []
        total_manual_minutes, total_auto_seconds = 0, 0

        for action_name in playbook:
            action_meta = ACTIONS[action_name]
            total_manual_minutes += action_meta["manual_minutes"]

            if action_meta["blast_radius"] >= HUMAN_APPROVAL_THRESHOLD:
                # High blast radius -> human-in-the-loop, do NOT auto-execute
                entry = {
                    "incident_id": incident_id, "action": action_name, "target": target,
                    "decision": "QUEUED_FOR_HUMAN_APPROVAL",
                    "reason": f"blast_radius={action_meta['blast_radius']} >= threshold={HUMAN_APPROVAL_THRESHOLD}",
                    "mitre_technique": mitre_technique, "severity": severity
                }
                self._log(entry)
                self.pending_human_approval.append(entry)
                queued.append(action_name)
            else:
                # Low/medium blast radius -> auto-execute immediately
                start = time.time()
                self.network_state.apply_action(action_name, target)
                total_auto_seconds += action_meta["auto_seconds"]
                entry = {
                    "incident_id": incident_id, "action": action_name, "target": target,
                    "decision": "AUTO_EXECUTED",
                    "reason": f"blast_radius={action_meta['blast_radius']} < threshold={HUMAN_APPROVAL_THRESHOLD}",
                    "mitre_technique": mitre_technique, "severity": severity
                }
                self._log(entry)
                executed.append(action_name)

        automatable_minutes = sum(
            ACTIONS[a]["manual_minutes"] for a in executed
        )
        automated_seconds = sum(ACTIONS[a]["auto_seconds"] for a in executed)
        time_saved_minutes = automatable_minutes - (automated_seconds / 60)

        return {
            "incident_id": incident_id,
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

    def get_audit_trail(self):
        return self.audit_log


if __name__ == "__main__":
    orchestrator = IncidentResponseOrchestrator()

    print("=== Simulating incident response for 3 attributed threats ===\n")

    incidents = [
        {"incident_id": "INC-001", "target": "host-10.0.4.22", "tactics": ["credential-access"],
         "severity": "high", "mitre_technique": "T1110 - Brute Force"},
        {"incident_id": "INC-002", "target": "host-10.0.7.15", "tactics": ["stealth", "privilege-escalation"],
         "severity": "critical", "mitre_technique": "T1055 - Process Injection"},
        {"incident_id": "INC-003", "target": "203.0.113.45", "tactics": ["exfiltration"],
         "severity": "critical", "mitre_technique": "T1041 - Exfiltration Over C2 Channel"},
    ]

    for inc in incidents:
        result = orchestrator.respond(**inc)
        print(f"--- {inc['incident_id']} ({inc['mitre_technique']}) ---")
        print(f"  Auto-executed: {result['auto_executed']}")
        print(f"  Queued for human approval: {result['queued_for_human_approval']}")
        print(f"  Manual baseline: {result['estimated_manual_response_minutes']} min | "
              f"Automated: {result['automated_response_seconds']}s | "
              f"Time saved (automatable subset): {result['time_saved_on_automatable_actions_minutes']} min\n")

    print("=== Network state after all responses (simulated) ===")
    print(json.dumps(orchestrator.network_state.snapshot(), indent=2))

    print(f"\n=== {len(orchestrator.pending_human_approval)} actions awaiting human approval ===")
    for p in orchestrator.pending_human_approval:
        print(f"  {p['incident_id']}: {p['action']} on {p['target']} ({p['reason']})")

    print(f"\n=== Full audit trail: {len(orchestrator.audit_log)} logged decisions ===")
    with open("audit_trail_sample.json", "w") as f:
        json.dump(orchestrator.get_audit_trail(), f, indent=2)
    print("Saved audit_trail_sample.json")
