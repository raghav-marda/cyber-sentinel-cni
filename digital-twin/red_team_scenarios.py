"""
Red-Team Scenario Testing
Module 5 — Cyber Resilience Digital Twin

Runs named, realistic attack scenarios end-to-end against the topology and
estimates business impact — combining the attack path (this module),
REAL detection rates by attack category (Module 1's actual evaluated
numbers, not assumptions), and asset criticality — to answer the
question a CISO actually asks: "if this scenario happened, how bad
would it be, and would we even notice in time?"
"""

import json
from topology import build_topology_graph
from attack_path_simulator import load_vulnerability_weights, weighted_graph, find_attack_paths

# Module 1's ACTUAL measured detection rates by attack category
# (from anomaly-detection/rigorous_evaluation_summary.json / advanced_evaluation results)
MODULE1_DETECTION_RATES = {
    "DoS": 0.793,
    "Probe": 0.883,
    "R2L": 0.086,
    "U2R": 0.284,
}

SCENARIOS = [
    {
        "name": "Ransomware via phishing email",
        "entry_point": "MAIL-01",
        "primary_attack_category": "R2L",
        "narrative": "Phishing email compromises a user credential on the mail server, "
                     "attacker pivots to the domain controller, then to backup and database systems."
    },
    {
        "name": "Compromised VPN credentials (insider-adjacent)",
        "entry_point": "VPN-GW-01",
        "primary_attack_category": "R2L",
        "narrative": "Stolen VPN credentials give direct internal network access, "
                     "bypassing perimeter defenses entirely."
    },
    {
        "name": "Web portal exploitation (opportunistic)",
        "entry_point": "WEB-01",
        "primary_attack_category": "DoS",
        "narrative": "Public-facing web portal is exploited directly, attacker pivots "
                     "to the citizen records database."
    },
]


def run_scenario(scenario, WG):
    """Computes reachable critical assets from this entry point + business impact + detection likelihood."""
    paths = find_attack_paths(WG, entry_point=scenario["entry_point"])
    reachable = {t: r for t, r in paths.items() if r["path"] is not None}

    total_criticality_at_risk = 0
    for target in reachable:
        criticality = WG.nodes[target].get("criticality", 0)
        total_criticality_at_risk += criticality

    detection_prob = MODULE1_DETECTION_RATES.get(scenario["primary_attack_category"], 0.5)

    return {
        "scenario": scenario["name"],
        "narrative": scenario["narrative"],
        "entry_point": scenario["entry_point"],
        "critical_assets_reachable": list(reachable.keys()),
        "total_criticality_at_risk": total_criticality_at_risk,
        "module1_detection_probability": detection_prob,
        "expected_undetected_risk": round(total_criticality_at_risk * (1 - detection_prob), 2),
        "paths": {t: r["path"] for t, r in reachable.items()}
    }


if __name__ == "__main__":
    G = build_topology_graph()
    vuln_weights = load_vulnerability_weights()
    WG = weighted_graph(G, vuln_weights)

    print("=" * 100)
    print("RED-TEAM SCENARIO TESTING")
    print("=" * 100)

    all_results = []
    for scenario in SCENARIOS:
        result = run_scenario(scenario, WG)
        all_results.append(result)

        print(f"\n--- {result['scenario']} ---")
        print(f"  {scenario['narrative']}")
        print(f"  Entry point: {result['entry_point']}")
        print(f"  Critical assets reachable: {result['critical_assets_reachable']}")
        print(f"  Total criticality at risk: {result['total_criticality_at_risk']}")
        print(f"  Module 1 detection probability for this attack class ({scenario['primary_attack_category']}): "
              f"{result['module1_detection_probability']*100:.1f}%")
        print(f"  Expected undetected risk (criticality x (1-detection prob)): {result['expected_undetected_risk']}")

    ranked = sorted(all_results, key=lambda r: r["expected_undetected_risk"], reverse=True)
    print("\n" + "=" * 100)
    print("SCENARIOS RANKED BY EXPECTED UNDETECTED RISK (highest priority for investment first)")
    print("=" * 100)
    for i, r in enumerate(ranked, 1):
        print(f"  #{i} {r['scenario']}: expected undetected risk = {r['expected_undetected_risk']}")

    print("\n>> Note: the phishing/R2L scenarios rank highest not because they reach the most "
          "assets, but because Module 1 only detects 8.6% of R2L-category attacks — a real, "
          "measured weakness, not a hypothetical one. This is exactly the kind of insight a "
          "digital twin should surface: risk is a function of BOTH reachability and detectability.")

    with open("red_team_scenario_results.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print("\nSaved red_team_scenario_results.json")
