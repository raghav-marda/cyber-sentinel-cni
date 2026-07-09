"""
Security Investment Impact Assessment ("What-If" Scenario Testing)
Module 5 — Cyber Resilience Digital Twin

This is the part of the problem statement that matters most for a
decision-maker: not just "here's an attack path" but "here's what
actually improves if we spend money on X." Tests three realistic,
budget-scale interventions against the SAME topology and re-runs the
attack path analysis to show a genuine before/after — not a hand-wave.

Scenarios tested:
1. IT/OT network segmentation (cut the LNX-APP-01 -> SCADA-01 link,
   the exact pattern responsible for real-world ICS incidents like the
   2015 Ukraine grid attack)
2. Patch the top-3 highest-risk CVEs from Module 4's remediation queue
3. Both combined
"""

import sys
sys.path.append("../vulnerability-prioritization")

import copy
import json
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from topology import build_topology_graph, get_critical_targets
from attack_path_simulator import load_vulnerability_weights, weighted_graph, find_attack_paths, find_choke_points


def scenario_baseline():
    G = build_topology_graph()
    vuln_weights = load_vulnerability_weights()
    return weighted_graph(G, vuln_weights)


def scenario_it_ot_segmentation():
    """Removes the IT->OT bridge — the single highest-leverage architectural fix."""
    WG = scenario_baseline()
    if WG.has_edge("LNX-APP-01", "SCADA-01"):
        WG.remove_edge("LNX-APP-01", "SCADA-01")
    return WG


def scenario_patch_top_cves(n=3):
    """
    Simulates patching the top-N highest-risk CVEs from Module 4's queue —
    for any asset whose worst CVE gets patched, its exploit-ease cost reverts
    to a hard-to-exploit baseline (9.0) instead of the current inflated-risk value.
    """
    try:
        queue = pd.read_csv("../vulnerability-prioritization/remediation_queue.csv")
    except FileNotFoundError:
        print("Run Module 4's risk_ranking.py first.")
        return scenario_baseline()

    top_n_assets = queue.sort_values("contextualized_risk_score", ascending=False).head(n)["asset_id"].tolist()

    G = build_topology_graph()
    vuln_weights = load_vulnerability_weights()
    for asset_id in top_n_assets:
        vuln_weights[asset_id] = 9.0  # patched -> hard to exploit
    return weighted_graph(G, vuln_weights), top_n_assets


def scenario_both(n=3):
    WG, patched = scenario_patch_top_cves(n)
    if WG.has_edge("LNX-APP-01", "SCADA-01"):
        WG.remove_edge("LNX-APP-01", "SCADA-01")
    return WG, patched


def compare_scenarios():
    baseline = scenario_baseline()
    segmented = scenario_it_ot_segmentation()
    patched, patched_assets = scenario_patch_top_cves(n=3)
    combined, _ = scenario_both(n=3)

    scenarios = {
        "Baseline (current state)": baseline,
        "IT/OT segmentation only": segmented,
        f"Patch top-3 CVEs only ({', '.join(patched_assets)})": patched,
        "Segmentation + patching (combined)": combined,
    }

    results = {}
    for name, WG in scenarios.items():
        paths = find_attack_paths(WG)
        reachable = {t: r for t, r in paths.items() if r["path"] is not None}
        avg_cost = round(sum(r["total_exploit_cost"] for r in reachable.values()) / len(reachable), 2) if reachable else None
        results[name] = {
            "critical_targets_still_reachable": len(reachable),
            "critical_targets_total": len(paths),
            "average_exploit_cost_to_reachable_targets": avg_cost,
            "path_details": {t: r["path"] for t, r in paths.items()}
        }
    return results


if __name__ == "__main__":
    print("Running 4 scenarios against the SAME topology: baseline, segmentation, patching, combined\n")
    results = compare_scenarios()

    print("=" * 100)
    print("SCENARIO COMPARISON")
    print("=" * 100)
    for name, r in results.items():
        print(f"\n{name}:")
        print(f"  Critical targets still reachable from INTERNET: {r['critical_targets_still_reachable']}/{r['critical_targets_total']}")
        print(f"  Average exploit cost to reach them: {r['average_exploit_cost_to_reachable_targets']}")
        for target, path in r["path_details"].items():
            status = " -> ".join(path) if path else "NO PATH (blocked)"
            print(f"    {target}: {status}")

    # Visualization: reachability + cost comparison
    names = list(results.keys())
    reachable_counts = [results[n]["critical_targets_still_reachable"] for n in names]
    avg_costs = [results[n]["average_exploit_cost_to_reachable_targets"] or 0 for n in names]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    short_names = ["Baseline", "Segmentation\nonly", "Patch top-3\nCVEs only", "Both\ncombined"]

    axes[0].bar(short_names, reachable_counts, color=["#c0392b", "#e67e22", "#e67e22", "#27ae60"])
    axes[0].set_ylabel("Critical assets still reachable")
    axes[0].set_title("Reachability of Mission-Critical Assets from Internet")
    for i, v in enumerate(reachable_counts):
        axes[0].text(i, v + 0.05, str(v), ha="center")

    axes[1].bar(short_names, avg_costs, color=["#c0392b", "#e67e22", "#e67e22", "#27ae60"])
    axes[1].set_ylabel("Average exploit cost (higher = harder)")
    axes[1].set_title("Average Difficulty of Reaching Critical Assets")
    for i, v in enumerate(avg_costs):
        axes[1].text(i, v + 0.2, str(v), ha="center")

    plt.tight_layout()
    plt.savefig("scenario_comparison.png", dpi=150)
    plt.close()
    print("\nSaved scenario_comparison.png")

    with open("digital_twin_scenario_summary.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("Saved digital_twin_scenario_summary.json")
