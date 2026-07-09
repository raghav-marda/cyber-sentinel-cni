"""
Attack Path Simulation
Module 5 — Cyber Resilience Digital Twin

Simulates how an attacker could move from an entry point (typically an
Internet-facing asset) to a mission-critical target, using the topology
graph. Each hop's "cost" (difficulty) is derived from REAL vulnerability
data pulled from Module 4's remediation queue — a hop through an asset
with an actively-exploited (CISA KEV) vulnerability is modeled as much
easier than a hop through a well-patched one. This is what lets the twin
answer "what's our actual weakest path to the SCADA server" instead of
just "what's topologically reachable."
"""

import sys
sys.path.append("../vulnerability-prioritization")

import networkx as nx
import pandas as pd
from topology import build_topology_graph, get_critical_targets


def load_vulnerability_weights():
    """
    Pulls Module 4's actual scored remediation queue and derives a per-asset
    'exploit ease' weight: the LOWER the weight, the EASIER that asset is
    to compromise (i.e. its highest contextualized risk score dominates).
    Falls back to a neutral weight for assets with no matched CVEs.
    """
    try:
        queue = pd.read_csv("../vulnerability-prioritization/remediation_queue.csv")
    except FileNotFoundError:
        print("Warning: remediation_queue.csv not found — run Module 4's risk_ranking.py first. Using neutral weights.")
        return {}

    # Higher contextualized_risk_score -> asset is easier to compromise -> lower graph edge cost
    max_risk_by_asset = queue.groupby("asset_id")["contextualized_risk_score"].max().to_dict()
    weights = {}
    for asset_id, risk in max_risk_by_asset.items():
        # Invert: risk 100 -> cost ~1 (trivial to exploit), risk 0 -> cost ~10 (hard)
        weights[asset_id] = round(max(1.0, 10 - (risk / 100 * 9)), 2)
    return weights


def weighted_graph(G, vuln_weights, default_weight=8.0):
    """Assigns an edge weight = the target node's exploit-ease cost."""
    WG = G.copy()
    for u, v in WG.edges():
        WG.edges[u, v]["weight"] = vuln_weights.get(v, default_weight)
    return WG


def find_attack_paths(WG, entry_point="INTERNET", targets=None, top_k=1):
    """
    Finds the lowest-cost (easiest) attack path from entry_point to each
    critical target, using Dijkstra's shortest-path over exploit-ease weights.
    """
    if targets is None:
        targets = get_critical_targets(WG)

    results = {}
    for target in targets:
        try:
            path = nx.shortest_path(WG, source=entry_point, target=target, weight="weight")
            cost = nx.shortest_path_length(WG, source=entry_point, target=target, weight="weight")
            results[target] = {"path": path, "total_exploit_cost": round(cost, 2), "hops": len(path) - 1}
        except nx.NetworkXNoPath:
            results[target] = {"path": None, "total_exploit_cost": None, "hops": None}
    return results


def find_choke_points(WG):
    """
    Betweenness centrality: which non-critical asset sits on the MOST
    attack paths to critical targets? This is the single highest-leverage
    place to add a control (segmentation, monitoring) because it affects
    every path that flows through it.
    """
    centrality = nx.betweenness_centrality(WG, weight="weight")
    ranked = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
    return ranked


if __name__ == "__main__":
    G = build_topology_graph()
    vuln_weights = load_vulnerability_weights()
    print(f"Loaded exploit-ease weights for {len(vuln_weights)} assets from Module 4's real vulnerability data:")
    for asset, w in sorted(vuln_weights.items(), key=lambda x: x[1]):
        print(f"  {asset}: cost={w} (lower = easier to exploit)")

    WG = weighted_graph(G, vuln_weights)

    print("\n" + "=" * 90)
    print("ATTACK PATHS: cheapest route from INTERNET to each mission-critical asset")
    print("=" * 90)
    paths = find_attack_paths(WG)
    for target, result in sorted(paths.items(), key=lambda x: (x[1]["total_exploit_cost"] or 999)):
        if result["path"]:
            print(f"\n  Target: {target} (total exploit cost={result['total_exploit_cost']}, {result['hops']} hops)")
            print(f"  Path: {' -> '.join(result['path'])}")
        else:
            print(f"\n  Target: {target} — NO PATH FOUND (isolated)")

    print("\n" + "=" * 90)
    print("CHOKE POINTS: assets with highest betweenness centrality (best place to add controls)")
    print("=" * 90)
    choke_points = find_choke_points(WG)
    for asset, score in choke_points[:5]:
        if score > 0:
            print(f"  {asset}: centrality={round(score, 4)}")
