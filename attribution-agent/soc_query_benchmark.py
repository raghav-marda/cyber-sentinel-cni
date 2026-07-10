"""
Realistic SOC Query Benchmark
Module 2 — honest, real-world comparison of TF-IDF vs semantic retrieval

The held-out paraphrase evaluation (rigorous_evaluation.py) tests something
narrower than it looks: whether a system can recognize a technique's OWN
distinctive vocabulary. On a small 697-document corpus, Word2Vec can learn
document-specific word associations that inflate that score without
reflecting real generalization — exactly what happened (92.7% top-1 there
vs visibly shakier results on naturally-phrased queries during a manual
sanity check).

This benchmark instead uses 20 hand-written queries phrased the way a SOC
analyst would actually describe behaviour (not paraphrased ATT&CK prose),
each with a manually verified correct MITRE technique ID, to get an honest
answer to "which retrieval approach should actually ship."
"""

import json
from attribution_agent import AttributionAgent
from semantic_embeddings import SemanticAttributionIndex
from mitre_parser import load_stix_bundle, parse_techniques

MITRE_PATH = "../data/mitre-cti/enterprise-attack/enterprise-attack.json"

# (query, correct MITRE technique ID) — written independently of ATT&CK's own phrasing
SOC_BENCHMARK = [
    ("repeated failed logins followed by one successful login with valid creds", "T1110"),
    ("someone is guessing passwords against our login page", "T1110"),
    ("attacker is using stolen but valid account credentials to log in", "T1078"),
    ("a process injected itself into another process's memory to hide", "T1055"),
    ("malware is trying to escalate to root/admin privileges", "T1068"),
    ("large amount of data being sent to an external server we don't recognize", "T1041"),
    ("host is scanning many ports across the internal subnet", "T1046"),
    ("attacker is probing which hosts and services exist on the network", "T1595"),
    ("phishing email with a malicious link sent to employees", "T1566"),
    ("ransomware encrypted files across multiple systems", "T1486"),
    ("attacker moved from one compromised machine to another using RDP", "T1021"),
    ("command and control traffic disguised as normal web traffic", "T1071"),
    ("attacker is deleting log files to cover their tracks", "T1070"),
    ("a scheduled task was created to maintain access after reboot", "T1053"),
    ("attacker dumped credentials from memory on a compromised host", "T1003"),
    ("suspicious PowerShell script execution with obfuscated code", "T1059"),
    ("attacker is flooding a server with traffic to take it offline", "T1499"),
    ("unauthorized firmware modification on a network device", "T1542"),
    ("attacker is using a valid but unusual remote desktop session", "T1021.001"),
    ("data was archived and compressed before being exfiltrated", "T1560"),
]


def evaluate_benchmark(retrieve_fn, benchmark, top_k=3):
    top1, top3 = 0, 0
    details = []
    for query, correct_id in benchmark:
        results = retrieve_fn(query, top_k=top_k)
        retrieved_ids = [r["mitre_id"] for r in results]
        is_top1 = len(retrieved_ids) > 0 and retrieved_ids[0] == correct_id
        is_top3 = correct_id in retrieved_ids
        top1 += int(is_top1)
        top3 += int(is_top3)
        details.append({"query": query, "expected": correct_id, "retrieved": retrieved_ids,
                         "top1_hit": is_top1, "top3_hit": is_top3})
    n = len(benchmark)
    return {"top1_accuracy": round(top1 / n, 4), "top3_accuracy": round(top3 / n, 4), "details": details}


if __name__ == "__main__":
    objects = load_stix_bundle(MITRE_PATH)
    techniques = parse_techniques(objects)

    print("Building both retrieval systems...")
    tfidf_agent = AttributionAgent()
    semantic_index = SemanticAttributionIndex(techniques)

    print(f"\nRunning {len(SOC_BENCHMARK)}-query hand-labeled SOC benchmark on both systems...\n")

    tfidf_scores = evaluate_benchmark(lambda q, top_k=3: tfidf_agent.retrieve_techniques(q, top_k=top_k), SOC_BENCHMARK)
    semantic_scores = evaluate_benchmark(semantic_index.retrieve, SOC_BENCHMARK)

    print("=" * 90)
    print("RESULTS: hand-labeled realistic SOC query benchmark (20 queries)")
    print("=" * 90)
    print(f"TF-IDF + keyword boost (current production): top1={tfidf_scores['top1_accuracy']*100:.1f}%, top3={tfidf_scores['top3_accuracy']*100:.1f}%")
    print(f"Semantic Word2Vec (from scratch):            top1={semantic_scores['top1_accuracy']*100:.1f}%, top3={semantic_scores['top3_accuracy']*100:.1f}%")

    print("\n--- Per-query breakdown ---")
    for t, s in zip(tfidf_scores["details"], semantic_scores["details"]):
        agree = "✅" if t["top1_hit"] else ("〜" if t["top3_hit"] else "❌")
        agree2 = "✅" if s["top1_hit"] else ("〜" if s["top3_hit"] else "❌")
        print(f"  TF-IDF {agree} | Semantic {agree2} | \"{t['query'][:55]}...\" (expected {t['expected']})")

    verdict = "semantic" if semantic_scores["top3_accuracy"] > tfidf_scores["top3_accuracy"] else "tfidf"
    print(f"\n=== VERDICT: on realistic SOC phrasing (not paraphrased ATT&CK text), "
          f"{'semantic embeddings win' if verdict=='semantic' else 'TF-IDF + keyword boost remains the better production choice'} ===")

    with open("soc_benchmark_comparison.json", "w") as f:
        json.dump({
            "tfidf_keyword_boost": {"top1_accuracy": tfidf_scores["top1_accuracy"], "top3_accuracy": tfidf_scores["top3_accuracy"]},
            "semantic_word2vec": {"top1_accuracy": semantic_scores["top1_accuracy"], "top3_accuracy": semantic_scores["top3_accuracy"]},
            "verdict": verdict,
            "query_details": tfidf_scores["details"]
        }, f, indent=2)
    print("Saved soc_benchmark_comparison.json")
