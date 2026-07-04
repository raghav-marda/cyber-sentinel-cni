"""
MITRE ATT&CK STIX Data Parser
Module 2 — APT Campaign Attribution & Prediction Agent (Point 2 of PS7)

Parses the MITRE ATT&CK Enterprise STIX bundle into clean, queryable
structures: techniques, tactics, mitigations, and their relationships.
"""

import json

# Canonical attack progression order (kill-chain sequence used by MITRE ATT&CK)
KILL_CHAIN_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-impairment", "stealth",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact"
]


def load_stix_bundle(path):
    with open(path) as f:
        data = json.load(f)
    return data["objects"]


def parse_techniques(objects):
    """Extract clean technique records: id, name, description, tactics, mitre_id."""
    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        mitre_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break
        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]
        techniques.append({
            "stix_id": obj["id"],
            "mitre_id": mitre_id,
            "name": obj["name"],
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", [])
        })
    return techniques


def parse_mitigations(objects):
    """Extract course-of-action (mitigation) records."""
    mitigations = {}
    for obj in objects:
        if obj.get("type") != "course-of-action":
            continue
        mitigations[obj["id"]] = {
            "name": obj["name"],
            "description": obj.get("description", "")
        }
    return mitigations


def parse_technique_to_mitigation_map(objects, mitigations):
    """
    Use 'relationship' objects (type: mitigates) to map technique STIX id ->
    list of applicable mitigations.
    """
    tech_to_mitigations = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        source = obj["source_ref"]  # course-of-action
        target = obj["target_ref"]  # attack-pattern
        if source in mitigations:
            tech_to_mitigations.setdefault(target, []).append(mitigations[source]["name"])
    return tech_to_mitigations


def parse_groups(objects):
    """Extract intrusion-set (known threat actor group) records."""
    groups = []
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        groups.append({
            "stix_id": obj["id"],
            "name": obj["name"],
            "description": obj.get("description", "")
        })
    return groups


def parse_group_technique_usage(objects):
    """Map intrusion-set (group) -> techniques they're known to use ('uses' relationships)."""
    group_techniques = {}
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if obj["source_ref"].startswith("intrusion-set") and obj["target_ref"].startswith("attack-pattern"):
            group_techniques.setdefault(obj["source_ref"], []).append(obj["target_ref"])
    return group_techniques


def predict_next_tactics(current_tactic, n=2):
    """
    Predict likely next-stage tactics based on canonical MITRE kill-chain ordering.
    E.g. if current stage is 'initial-access', next likely stages are
    'execution' and 'persistence'.
    """
    if current_tactic not in KILL_CHAIN_ORDER:
        return []
    idx = KILL_CHAIN_ORDER.index(current_tactic)
    return KILL_CHAIN_ORDER[idx + 1: idx + 1 + n]


if __name__ == "__main__":
    objects = load_stix_bundle("../data/mitre-cti/enterprise-attack/enterprise-attack.json")
    techniques = parse_techniques(objects)
    mitigations = parse_mitigations(objects)
    tech_to_mit = parse_technique_to_mitigation_map(objects, mitigations)
    groups = parse_groups(objects)
    group_tech = parse_group_technique_usage(objects)

    print(f"Parsed {len(techniques)} active techniques")
    print(f"Parsed {len(mitigations)} mitigations")
    print(f"Techniques with at least one mapped mitigation: {len(tech_to_mit)}")
    print(f"Parsed {len(groups)} known threat actor groups")
    print(f"Groups with mapped technique usage: {len(group_tech)}")

    print("\nExample technique:")
    t = techniques[10]
    print(f"  {t['mitre_id']} - {t['name']} (tactics: {t['tactics']})")
    print(f"  Mitigations: {tech_to_mit.get(t['stix_id'], ['None mapped'])}")

    print("\nExample kill-chain prediction:")
    print("  Current: initial-access -> Next likely:", predict_next_tactics("initial-access"))
    print("  Current: execution -> Next likely:", predict_next_tactics("execution"))
