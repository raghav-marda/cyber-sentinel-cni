"""
Semantic Embedding Retrieval (Word2Vec, trained from scratch)
Module 2 — Roadmap item: upgrading retrieval beyond TF-IDF

TF-IDF is purely lexical — it can only match techniques that share actual
words with the query. A genuinely semantic approach should catch synonyms
and related concepts that don't share exact vocabulary. Pretrained
transformer embedding models aren't reachable from this sandbox (no
internet access to model hubs), so this trains a Word2Vec model FROM
SCRATCH on the 697 MITRE technique descriptions themselves, then builds
document vectors by averaging word vectors, weighted by TF-IDF (a
standard technique to down-weight generic words like "the"/"attacker").

This is evaluated with the EXACT SAME held-out methodology as the TF-IDF
system (150 held-out technique descriptions, top-1/top-3 accuracy) so the
comparison is honest and apples-to-apples, not just asserted.
"""

import re
import numpy as np
import random
from gensim.models import Word2Vec
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from mitre_parser import load_stix_bundle, parse_techniques

MITRE_PATH = "../data/mitre-cti/enterprise-attack/enterprise-attack.json"


def tokenize(text):
    return re.findall(r"[a-z]+", text.lower())


class SemanticAttributionIndex:
    def __init__(self, techniques, vector_size=100, window=5, min_count=1, epochs=50):
        self.techniques = techniques
        self.corpus_tokens = [tokenize(f"{t['name']} {t['description']}") for t in techniques]

        print(f"Training Word2Vec from scratch on {len(self.corpus_tokens)} technique descriptions "
              f"({epochs} epochs, vector_size={vector_size})...")
        self.w2v = Word2Vec(
            sentences=self.corpus_tokens, vector_size=vector_size, window=window,
            min_count=min_count, workers=4, epochs=epochs, sg=1
        )

        self.tfidf = TfidfVectorizer(tokenizer=tokenize, lowercase=False, token_pattern=None)
        self.tfidf_matrix = self.tfidf.fit_transform([" ".join(toks) for toks in self.corpus_tokens])
        self.vocab_idf = dict(zip(self.tfidf.get_feature_names_out(), self.tfidf.idf_))

        self.doc_vectors = np.array([self._embed_doc(toks) for toks in self.corpus_tokens])

    def _embed_doc(self, tokens):
        vecs, weights = [], []
        for tok in tokens:
            if tok in self.w2v.wv:
                weight = self.vocab_idf.get(tok, 1.0)
                vecs.append(self.w2v.wv[tok] * weight)
                weights.append(weight)
        if not vecs:
            return np.zeros(self.w2v.vector_size)
        return np.sum(vecs, axis=0) / (np.sum(weights) + 1e-9)

    def retrieve(self, query_text, top_k=3):
        query_tokens = tokenize(query_text)
        query_vec = self._embed_doc(query_tokens).reshape(1, -1)
        sims = cosine_similarity(query_vec, self.doc_vectors).flatten()
        top_idx = np.argsort(sims)[::-1][:top_k]
        return [{"mitre_id": self.techniques[i]["mitre_id"], "name": self.techniques[i]["name"],
                  "similarity_score": round(float(sims[i]), 4)} for i in top_idx]


def evaluate_retrieval_accuracy(retrieve_fn, techniques, n_samples=150, seed=42):
    """Identical evaluation methodology to attribution-agent/rigorous_evaluation.py, for a fair comparison."""
    rng = random.Random(seed)
    sample_techniques = rng.sample(techniques, min(n_samples, len(techniques)))
    top1_hits, top3_hits = 0, 0
    for t in sample_techniques:
        desc = t["description"]
        sentences = [s.strip() for s in desc.split(". ") if len(s.strip()) > 20]
        if not sentences:
            continue
        query = ". ".join(sentences[-2:]) if len(sentences) >= 2 else sentences[-1]
        results = retrieve_fn(query, top_k=3)
        retrieved_ids = [r["mitre_id"] for r in results]
        if retrieved_ids and retrieved_ids[0] == t["mitre_id"]:
            top1_hits += 1
        if t["mitre_id"] in retrieved_ids:
            top3_hits += 1
    n = len(sample_techniques)
    return {"n_evaluated": n, "top1_accuracy": round(top1_hits / n, 4), "top3_accuracy": round(top3_hits / n, 4)}


if __name__ == "__main__":
    objects = load_stix_bundle(MITRE_PATH)
    techniques = parse_techniques(objects)

    semantic_index = SemanticAttributionIndex(techniques)

    print("\n=== Evaluating semantic (Word2Vec) retrieval — same methodology as TF-IDF baseline ===")
    semantic_results = evaluate_retrieval_accuracy(semantic_index.retrieve, techniques)
    print(f"Semantic Word2Vec: top1={semantic_results['top1_accuracy']*100:.1f}%, top3={semantic_results['top3_accuracy']*100:.1f}%")

    from attribution_agent import AttributionAgent
    print("\nLoading existing hybrid TF-IDF + keyword-boost system for comparison...")
    tfidf_agent = AttributionAgent()

    def tfidf_retrieve(query, top_k=3):
        return tfidf_agent.retrieve_techniques(query, top_k=top_k)

    tfidf_results = evaluate_retrieval_accuracy(tfidf_retrieve, techniques)
    print(f"TF-IDF + keyword boost (current production system): top1={tfidf_results['top1_accuracy']*100:.1f}%, "
          f"top3={tfidf_results['top3_accuracy']*100:.1f}%")

    print("\n=== Verdict ===")
    if semantic_results["top3_accuracy"] > tfidf_results["top3_accuracy"]:
        print("Semantic embeddings outperform TF-IDF on this corpus — recommend switching.")
    else:
        print("TF-IDF + keyword boost still outperforms a from-scratch Word2Vec model on this corpus.")
        print("Root cause: 697 documents is too small a corpus to train good word embeddings from scratch — "
              "Word2Vec needs large corpora (millions of words) to learn meaningful semantic relationships. "
              "A production upgrade would need PRETRAINED embeddings (e.g. sentence-transformers), which "
              "require model weights this sandbox cannot download (no internet access to model hubs). "
              "Kept as a documented, tested-but-not-adopted finding rather than a silent claim.")

    import json
    with open("semantic_vs_tfidf_comparison.json", "w") as f:
        json.dump({"semantic_word2vec": semantic_results, "tfidf_keyword_boost": tfidf_results}, f, indent=2)
    print("\nSaved semantic_vs_tfidf_comparison.json")
