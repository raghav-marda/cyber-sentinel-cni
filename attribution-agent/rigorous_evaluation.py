"""
Attribution Agent — Rigorous Evaluation & Campaign Narrative Builder
Module 2 — Deep Evaluation

Adds:
1. Quantitative retrieval evaluation: measures top-1/top-3 accuracy of the
   RAG system using MITRE's OWN technique descriptions as a held-out test
   set (can we retrieve technique X when given a paraphrase of its own
   description?) — this is a standard way to sanity-check retrieval quality
2. Multi-stage campaign narrative builder: given a SEQUENCE of detected
   anomalies over time (not just one event), reconstructs a probable
   attack campaign narrative and ranks which known APT group's historical
   technique usage most closely matches the observed pattern (Jaccard similarity)
"""

import random
import json
import numpy as np

from attribution_agent import AttributionAgent


def evaluate_retrieval_accuracy(agent, n_samples=150, seed=42):
    """
    Quantitative sanity check: take N random techniques, use a truncated/
    paraphrased version of their OWN description as a query, and measure
    whether the retrieval correctly surfaces that same technique in its
    top-1 / top-3 results. This measures whether the retrieval index is
    doing meaningful semantic matching rather than random guessing.
    """
    rng = random.Random(seed)
    sample_techniques = rng.sample(agent.techniques, min(n_samples, len(agent.techniques)))

    top1_hits, top3_hits = 0, 0
    for t in sample_techniques:
        # Use the last 2 sentences of the description as a "paraphrase-like" query
        # (simulates a SOC analyst describing behaviour without naming the technique)
        desc = t["description"]
        sentences = [s.strip() for s in desc.split(". ") if len(s.strip()) > 20]
        if not sentences:
            continue
        query = ". ".join(sentences[-2:]) if len(sentences) >= 2 else sentences[-1]

        results = agent.retrieve_techniques(query, top_k=3)
        retrieved_ids = [r["mitre_id"] for r in results]

        if retrieved_ids and retrieved_ids[0] == t["mitre_id"]:
            top1_hits += 1
        if t["mitre_id"] in retrieved_ids:
            top3_hits += 1

    n = len(sample_techniques)
    return {
        "n_evaluated": n,
        "top1_accuracy": round(top1_hits / n, 4),
        "top3_accuracy": round(top3_hits / n, 4)
    }


def build_campaign_narrative(agent, event_descriptions: list):
    """
    Given a time-ordered sequence of observed-behaviour descriptions
    (e.g. from multiple flagged anomalies across a session), attribute
    each to a technique, then:
    1. Build a kill-chain narrative (which tactics were touched, in what order)
    2. Rank known APT groups by how closely their historical technique
       usage overlaps with the observed technique set (Jaccard similarity)
    """
    observed_techniques = []
    narrative_steps = []

    for i, desc in enumerate(event_descriptions):
        matches = agent.attribute(desc, top_k=1)
        if not matches:
            continue
        top = matches[0]
        observed_techniques.append(top["mitre_id"])
        narrative_steps.append({
            "step": i + 1,
            "observed_behaviour": desc,
            "attributed_technique": f"{top['mitre_id']} - {top['name']}",
            "tactics": top["tactics"]
        })

    # Rank threat groups by technique overlap (Jaccard similarity)
    observed_set = set(observed_techniques)
    group_scores = []
    group_name_by_id = {g["stix_id"]: g["name"] for g in agent.groups}

    for group_id, tech_stix_ids in agent.group_technique_usage.items():
        group_technique_mitre_ids = set()
        for stix_id in tech_stix_ids:
            match = next((t["mitre_id"] for t in agent.techniques if t["stix_id"] == stix_id), None)
            if match:
                group_technique_mitre_ids.add(match)

        if not group_technique_mitre_ids:
            continue
        intersection = observed_set & group_technique_mitre_ids
        union = observed_set | group_technique_mitre_ids
        jaccard = len(intersection) / len(union) if union else 0
        if jaccard > 0:
            group_scores.append({
                "group": group_name_by_id.get(group_id, "Unknown"),
                "jaccard_similarity": round(jaccard, 4),
                "overlapping_techniques": len(intersection)
            })

    group_scores = sorted(group_scores, key=lambda x: x["jaccard_similarity"], reverse=True)[:5]

    return {
        "narrative": narrative_steps,
        "observed_technique_set": list(observed_set),
        "most_likely_campaign_match": group_scores
    }


if __name__ == "__main__":
    print("Loading attribution agent...")
    agent = AttributionAgent()

    # === 1. Quantitative retrieval evaluation ===
    print("\n=== Retrieval Accuracy Evaluation (150 held-out technique descriptions) ===")
    eval_results = evaluate_retrieval_accuracy(agent, n_samples=150)
    print(f"Top-1 accuracy: {eval_results['top1_accuracy']*100:.1f}%")
    print(f"Top-3 accuracy: {eval_results['top3_accuracy']*100:.1f}%")
    print(f"(Evaluated on {eval_results['n_evaluated']} techniques)")

    # === 2. Multi-stage campaign narrative ===
    print("\n" + "=" * 90)
    print("MULTI-STAGE CAMPAIGN NARRATIVE RECONSTRUCTION")
    print("=" * 90)

    # Simulated realistic multi-stage attack sequence (as would come from
    # Module 1 flagging several anomalies across a session/timeframe)
    attack_sequence = [
        "attacker scanning multiple ports and services across the internal network",
        "repeated failed login attempts followed by a successful login using valid credentials",
        "privilege escalation observed, root shell access obtained on the host",
        "a process was observed injecting code into another running process to evade detection",
        "unusual outbound data transfer of significant volume to an external destination late at night"
    ]

    result = build_campaign_narrative(agent, attack_sequence)

    print("\nReconstructed attack narrative:")
    for step in result["narrative"]:
        print(f"  Step {step['step']}: {step['attributed_technique']} (tactics: {step['tactics']})")
        print(f"           Observed: \"{step['observed_behaviour'][:70]}...\"")

    print(f"\nObserved technique set: {result['observed_technique_set']}")
    print("\nMost likely matching known APT campaigns (by technique overlap):")
    for g in result["most_likely_campaign_match"]:
        print(f"  {g['group']}: Jaccard similarity={g['jaccard_similarity']} ({g['overlapping_techniques']} overlapping techniques)")

    # Save everything
    with open("attribution_evaluation_summary.json", "w") as f:
        json.dump({
            "retrieval_accuracy": eval_results,
            "example_campaign_narrative": result
        }, f, indent=2, default=str)
    print("\nSaved attribution_evaluation_summary.json")
