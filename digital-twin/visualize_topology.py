"""
Topology Visualization
Module 5 — Cyber Resilience Digital Twin

Renders the network topology graph with criticality-based color coding
and the baseline attack paths highlighted — for direct use in the
presentation deck and document.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from topology import build_topology_graph

CRITICALITY_COLORS = {
    0: "#7f8c8d", 1: "#95a5a6", 2: "#3498db", 3: "#f39c12", 4: "#e67e22", 5: "#c0392b"
}
ZONE_SHAPES = {"EXTERNAL": "s", "DMZ": "^", "IT": "o", "OT": "D"}


def draw_topology(G, save_path="topology_diagram.png"):
    pos = nx.spring_layout(G, seed=42, k=1.2)

    plt.figure(figsize=(11, 8))

    for zone, shape in ZONE_SHAPES.items():
        nodes = [n for n, d in G.nodes(data=True) if d.get("network_zone") == zone]
        colors = [CRITICALITY_COLORS[G.nodes[n]["criticality"]] for n in nodes]
        nx.draw_networkx_nodes(G, pos, nodelist=nodes, node_color=colors, node_shape=shape,
                                node_size=1800, edgecolors="black", linewidths=1.2)

    nx.draw_networkx_edges(G, pos, edge_color="gray", arrows=True, arrowsize=15, connectionstyle="arc3,rad=0.05")
    nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold")

    legend_elements = [
        plt.Line2D([0], [0], marker="s", color="w", markerfacecolor="gray", markersize=12, label="External/DMZ zone"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="gray", markersize=12, label="IT zone"),
        plt.Line2D([0], [0], marker="D", color="w", markerfacecolor="gray", markersize=12, label="OT zone (critical)"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="#c0392b", markersize=12, label="Criticality 5 (mission-critical)"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="#95a5a6", markersize=12, label="Criticality 1 (low)"),
    ]
    plt.legend(handles=legend_elements, loc="lower left", fontsize=8)
    plt.title("CNI Network Topology — Digital Twin (shapes=zone, color=criticality)")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()


if __name__ == "__main__":
    G = build_topology_graph()
    draw_topology(G)
    print("Saved topology_diagram.png")
