"""
Network Topology Model
Module 5 — Cyber Resilience Digital Twin (Point 5 of PS7)

Builds a graph representation of the CNI environment using Module 4's
REAL asset inventory (not a separate invented one — same 12 assets,
same criticality scores) plus realistic trust/connectivity relationships
between network zones (Internet -> DMZ -> IT -> OT). This is the "digital
twin" the problem statement asks for: a simulation of the security
architecture that supports attack-path modelling and what-if analysis
WITHOUT touching any real system.
"""

import sys
sys.path.append("../vulnerability-prioritization")

import networkx as nx
from asset_matcher import ASSET_INVENTORY

# Realistic connectivity: which assets can directly reach which others.
# Modeled on typical CNI network segmentation: Internet reaches DMZ only;
# DMZ can reach specific IT services; IT can reach OT ONLY through the
# historian/gateway pattern many real ICS environments still use in practice
# (a known root cause in real-world incidents like the 2015 Ukraine grid attack).
CONNECTIVITY = [
    ("INTERNET", "VPN-GW-01"),
    ("INTERNET", "WEB-01"),
    ("INTERNET", "FW-01"),
    ("FW-01", "VPN-GW-01"),
    ("FW-01", "WEB-01"),
    ("FW-01", "MAIL-01"),
    ("VPN-GW-01", "WIN-DC-01"),
    ("WEB-01", "DB-01"),
    ("MAIL-01", "WIN-DC-01"),
    ("WIN-DC-01", "DB-01"),
    ("WIN-DC-01", "BACKUP-01"),
    ("WIN-DC-01", "LNX-APP-01"),
    ("WIN-DC-01", "PRINT-01"),
    # The critical, commonly-real-world weak link: IT reaching into OT
    # via an engineering workstation / historian pattern
    ("LNX-APP-01", "SCADA-01"),
    ("SCADA-01", "PLC-01"),
    ("SCADA-01", "RTU-01"),
]


def build_topology_graph():
    """Constructs the directed graph: nodes = assets (+ Internet), edges = reachability."""
    G = nx.DiGraph()

    G.add_node("INTERNET", asset_name="Internet / external attacker origin", criticality=0, network_zone="EXTERNAL")
    for asset in ASSET_INVENTORY:
        G.add_node(asset["asset_id"], asset_name=asset["asset_name"],
                    criticality=asset["criticality"], network_zone=asset["network_zone"])

    G.add_edges_from(CONNECTIVITY)
    return G


def get_critical_targets(G, min_criticality=5):
    """OT/mission-critical assets — the assets an attacker is presumed to want to reach."""
    return [n for n, d in G.nodes(data=True) if d.get("criticality", 0) >= min_criticality]


if __name__ == "__main__":
    G = build_topology_graph()
    print(f"Topology graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    critical_targets = get_critical_targets(G)
    print(f"\nMission-critical (criticality=5) targets: {critical_targets}")

    print("\nNode details:")
    for n, d in G.nodes(data=True):
        print(f"  {n}: {d['asset_name']} (criticality={d['criticality']}, zone={d['network_zone']})")

    print("\nDirect connections from INTERNET:")
    print(f"  {list(G.successors('INTERNET'))}")
