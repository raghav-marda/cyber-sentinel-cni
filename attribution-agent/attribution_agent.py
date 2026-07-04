"""
APT Campaign Attribution & Prediction Agent
Module 2 — Point 2 of PS7

Given a free-text description of observed anomalous behaviour (from Module 1's
anomaly detection engine, or a SOC analyst's notes), this agent:
1. Retrieves the most likely matching MITRE ATT&CK technique(s) via TF-IDF
   similarity search over technique descriptions (RAG retrieval step)
2. Identifies known threat actor groups associated with that technique
3. Predicts likely next-stage attacker moves using kill-chain ordering
4. Recommends concrete defensive mitigations (pulled from MITRE's own
   course-of-action data — not hallucinated)
"""

import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from mitre_parser import (
    load_stix_bundle, parse_techniques, parse_mitigations,
    parse_technique_to_mitigation_map, parse_groups, parse_group_technique_usage,
    predict_next_tactics
)

MITRE_PATH = "../data/mitre-cti/enterprise-attack/enterprise-attack.json"


class AttributionAgent:
    def __init__(self, mitre_path=MITRE_PATH):
        objects = load_stix_bundle(mitre_path)
        self.techniques = parse_techniques(objects)
        self.mitigations = parse_mitigations(objects)
        self.tech_to_mitigations = parse_technique_to_mitigation_map(objects, self.mitigations)
        self.groups = parse_groups(objects)
        self.group_technique_usage = parse_group_technique_usage(objects)

        # Build reverse index: technique stix_id -> list of group names using it
        self.technique_to_groups = {}
        group_name_by_id = {g["stix_id"]: g["name"] for g in self.groups}
        for group_id, tech_ids in self.group_technique_usage.items():
            gname = group_name_by_id.get(group_id)
            if not gname:
                continue
            for tid in tech_ids:
                self.technique_to_groups.setdefault(tid, []).append(gname)

        # Build TF-IDF retrieval index over technique name (weighted 3x) + description
        # Weighting the name higher improves precision for short SOC-style queries
        # that use domain terminology close to official technique names.
        self.corpus = [f"{t['name']} {t['name']} {t['name']}. {t['description']}" for t in self.techniques]
        self.vectorizer = TfidfVectorizer(
            stop_words="english", max_features=8000, ngram_range=(1, 2),
            sublinear_tf=True, min_df=1
        )
        self.tfidf_matrix = self.vectorizer.fit_transform(self.corpus)

        # Curated keyword -> MITRE technique ID boost map for common SOC terminology.
        # Each entry is a set of words that must ALL appear (in any order/form) in the
        # query for the boost to trigger — more robust than exact-phrase matching.
        self.keyword_boosts = {
            frozenset(["port", "scan"]): ["T1046", "T1595"],
            frozenset(["network", "scan"]): ["T1046", "T1595"],
            frozenset(["brute", "force"]): ["T1110"],
            frozenset(["failed", "login"]): ["T1110"],
            frozenset(["valid", "credentials"]): ["T1078"],
            frozenset(["valid", "account"]): ["T1078"],
            frozenset(["privilege", "escalation"]): ["T1068", "T1055"],
            frozenset(["inject", "process"]): ["T1055"],
            frozenset(["inject", "code"]): ["T1055"],
            frozenset(["exfiltrat"]): ["T1041", "T1048"],
            frozenset(["large", "volume", "data"]): ["T1030", "T1041"],
            frozenset(["command", "control"]): ["T1071"],
            frozenset(["lateral", "movement"]): ["T1021"],
            frozenset(["phishing"]): ["T1566"],
            frozenset(["ransomware"]): ["T1486"],
            frozenset(["denial", "service"]): ["T1498", "T1499"],
        }

    def _apply_keyword_boost(self, query_text, results):
        """Re-rank/inject results based on curated keyword-set matches (flexible word matching)."""
        query_words = set(query_text.lower().replace(",", "").replace(".", "").split())
        boosted_ids = []
        for keyword_set, mitre_ids in self.keyword_boosts.items():
            # match if every keyword (or its stem) appears as a substring of some query word
            if all(any(kw in qw for qw in query_words) for kw in keyword_set):
                boosted_ids.extend(mitre_ids)
        if not boosted_ids:
            return results

        existing_ids = {r["mitre_id"] for r in results}
        for mid in boosted_ids:
            if mid in existing_ids:
                continue
            match = next((t for t in self.techniques if t["mitre_id"] == mid), None)
            if match:
                results.append({
                    "mitre_id": match["mitre_id"], "name": match["name"],
                    "tactics": match["tactics"], "similarity_score": 0.99,
                    "stix_id": match["stix_id"], "matched_via": "keyword_rule"
                })
        return sorted(results, key=lambda r: r["similarity_score"], reverse=True)

    def retrieve_techniques(self, query_text, top_k=5):
        """Core RAG retrieval step: find techniques most textually similar to the query,
        enhanced with a curated keyword boost layer for common SOC terminology."""
        query_vec = self.vectorizer.transform([query_text])
        sims = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        top_idx = np.argsort(sims)[::-1][:top_k]
        results = []
        for i in top_idx:
            t = self.techniques[i]
            results.append({
                "mitre_id": t["mitre_id"],
                "name": t["name"],
                "tactics": t["tactics"],
                "similarity_score": round(float(sims[i]), 4),
                "stix_id": t["stix_id"],
                "matched_via": "tfidf_similarity"
            })
        results = self._apply_keyword_boost(query_text, results)
        # Deduplicate by mitre_id, keeping highest similarity score
        seen = {}
        for r in results:
            if r["mitre_id"] not in seen or r["similarity_score"] > seen[r["mitre_id"]]["similarity_score"]:
                seen[r["mitre_id"]] = r
        deduped = sorted(seen.values(), key=lambda r: r["similarity_score"], reverse=True)
        return deduped[:top_k]

    def attribute(self, query_text, top_k=3):
        """
        Full attribution pipeline for an observed behaviour description.
        Returns matched techniques enriched with: known threat groups,
        predicted next-stage tactics, and recommended mitigations.
        """
        matches = self.retrieve_techniques(query_text, top_k=top_k)
        enriched = []
        for m in matches:
            groups = self.technique_to_groups.get(m["stix_id"], [])[:5]
            mitigations = self.tech_to_mitigations.get(m["stix_id"], [])[:5]

            next_tactics = []
            for tactic in m["tactics"]:
                next_tactics.extend(predict_next_tactics(tactic, n=2))
            next_tactics = list(dict.fromkeys(next_tactics))  # dedupe, preserve order

            enriched.append({
                **m,
                "known_threat_groups": groups if groups else ["No specific group attribution in dataset"],
                "predicted_next_tactics": next_tactics,
                "recommended_mitigations": mitigations if mitigations else ["No specific mitigation mapped"]
            })
        return enriched


if __name__ == "__main__":
    print("Loading MITRE ATT&CK data and building retrieval index...")
    agent = AttributionAgent()
    print(f"Ready. Indexed {len(agent.techniques)} techniques, {len(agent.groups)} threat groups.\n")

    # Test with realistic SOC-style observed-behaviour descriptions
    test_queries = [
        "Repeated failed login attempts followed by a successful login using valid credentials from an unusual external IP address",
        "Unusual outbound network traffic to an unknown external server transferring large volumes of data late at night",
        "A process was observed injecting code into another running process to evade antivirus detection",
        "Attacker scanning multiple ports across the internal network to identify open services"
    ]

    for q in test_queries:
        print("=" * 90)
        print("OBSERVED BEHAVIOUR:", q)
        results = agent.attribute(q, top_k=2)
        for r in results:
            print(f"\n  -> {r['mitre_id']} - {r['name']} (similarity={r['similarity_score']})")
            print(f"     Tactics: {r['tactics']}")
            print(f"     Known threat groups using this technique: {r['known_threat_groups']}")
            print(f"     Predicted next attacker moves (tactics): {r['predicted_next_tactics']}")
            print(f"     Recommended mitigations: {r['recommended_mitigations']}")
        print()
