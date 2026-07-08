# 🛡️ Cyber Sentinel CNI

**AI-Driven Cyber Resilience for Critical National Infrastructure**

![Status](https://img.shields.io/badge/status-in%20development-yellow)
![Hackathon](https://img.shields.io/badge/ET%20AI%20Hackathon-2026-blue)
![Problem Statement](https://img.shields.io/badge/PS-7-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-Hackathon%20Prototype-lightgrey)

> A behavioural intelligence platform that detects cyber threats to critical infrastructure **without relying on known malware signatures** — compressing detection-to-response time from weeks to minutes.

Built solo for **ET AI Hackathon 2026 — Problem Statement 7**.

---

## 📋 Table of Contents
- [Overview](#-overview)
- [Architecture](#-architecture)
- [Modules & Progress](#-modules--progress)
- [Key Results](#-key-results)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Datasets](#-datasets)
- [Roadmap](#-roadmap)

---

## 🎯 Overview

Critical national infrastructure — power grids, government systems, financial networks — faces attackers who deliberately operate "low and slow" to evade signature-based detection. CERT-In reported handling over **1.59 million cybersecurity incidents in 2023** alone, with most breaches discovered only weeks or months after initial compromise.

**Cyber Sentinel CNI** addresses this with a behavioural intelligence layer that:
1. Learns what *normal* network behaviour looks like — no attack signatures needed
2. Flags deviations in real time and explains *why* they're suspicious
3. Maps flagged behaviour to the **MITRE ATT&CK** framework to identify attacker techniques, likely next moves, and known threat actor associations
4. Recommends concrete, MITRE-sourced defensive mitigations
5. *(In progress)* Orchestrates automated containment, prioritizes vulnerabilities, and simulates attack paths on a digital twin

---

## 🏗️ Architecture

```
                    ┌─────────────────────────┐
                    │   Raw Network Traffic    │
                    │   (NSL-KDD / live feed)  │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   MODULE 1                │
                    │   Behavioural Anomaly     │
                    │   Detection Engine        │
                    │   (Ensemble: Statistical  │
                    │   Z-score + Isolation     │
                    │   Forest)                 │
                    └────────────┬─────────────┘
                                 │ flagged anomaly + severity
                    ┌────────────▼─────────────┐
                    │   Pipeline Bridge          │
                    │   (event → NL description) │
                    └────────────┬─────────────┘
                                 │ behaviour description
                    ┌────────────▼─────────────┐
                    │   MODULE 2                 │
                    │   APT Attribution Agent     │
                    │   (Hybrid RAG: TF-IDF +     │
                    │   keyword rules over MITRE  │
                    │   ATT&CK, 697 techniques)   │
                    └────────────┬─────────────┘
                                 │ technique + tactics + threat group
                    ┌────────────▼─────────────┐
                    │  MODULES 3-5 (in progress)  │
                    │  Incident Response          │
                    │  Orchestrator · Vuln         │
                    │  Prioritization · Digital    │
                    │  Twin                        │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   Unified Dashboard        │
                    └───────────────────────────┘
```

---

## 📦 Modules & Progress

| # | Module | Status | Depth |
|---|--------|--------|-------|
| 1 | **Behavioural Anomaly Detection Engine** | ✅ Complete | Full ML build — ensemble model, rigorous evaluation |
| 2 | **APT Campaign Attribution & Prediction Agent** | ✅ Complete | Full RAG build — hybrid retrieval, quantitatively evaluated |
| 3 | **Autonomous Incident Response Orchestrator** | ✅ Complete | Full SOAR build — MITRE-mapped playbooks, escalation gates, audited |
| 4 | **Government Infrastructure Vulnerability Prioritisation** | ✅ Complete | Full build — real NVD/CVSS-BT data, contextualized risk scoring |
| 5 | **Cyber Resilience Digital Twin** | 🔜 In progress | — |

See [`docs/SCOPE.md`](docs/SCOPE.md) for full scope and success criteria.

---

## 📊 Key Results

### Module 1 — Anomaly Detection (trained on normal-traffic-only baseline)

| Method | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| Statistical Z-score baseline | 0.851 | 0.858 | 0.854 | 0.894 |
| Isolation Forest | 0.974 | 0.648 | 0.778 | 0.939 |
| **Ensemble (final model)** | **0.871** | **0.878** | **0.874** | 0.935 |

**Detection rate by attack category:**
| DoS | Probe | R2L | U2R |
|---|---|---|---|
| 79.3% | 88.3% | 8.6%¹ | 28.4%¹ |

¹ *R2L/U2R attacks are low-volume and behaviourally subtle — a known, documented challenge in NSL-KDD research. Flagged here transparently as a limitation and future improvement area (see [Roadmap](#-roadmap)), not hidden.*

**Top features driving detection:** `dst_host_rerror_rate`, `dst_host_srv_rerror_rate`, `count`, `srv_rerror_rate` — all connection-error and traffic-pattern indicators, consistent with expected attack behaviour.

### Module 2 — APT Attribution Agent (RAG over MITRE ATT&CK, 697 techniques)

| Metric | Score |
|---|---|
| Top-1 retrieval accuracy | 62.7% |
| Top-3 retrieval accuracy | **96.0%** |
| Techniques indexed | 697 |
| Threat groups mapped | 189 |
| Mitigations linked | 268 |

*(Evaluated on 150 held-out technique descriptions — random-chance top-3 accuracy would be ~0.4%.)*

**Example — multi-stage campaign reconstruction:** given a sequence of 5 flagged anomalies, the agent correctly reconstructed the kill-chain (**Discovery → Credential Access → Privilege Escalation → Stealth → Exfiltration**) and ranked the closest-matching known APT groups by technique overlap (Jaccard similarity).

Full evaluation artifacts: [`anomaly-detection/rigorous_evaluation_summary.json`](anomaly-detection/rigorous_evaluation_summary.json), [`attribution-agent/attribution_evaluation_summary.json`](attribution-agent/attribution_evaluation_summary.json)

### Module 3 — Incident Response Orchestrator (evaluated on 20 real attack events, full pipeline)

| Metric | Result |
|---|---|
| Attacks detected & responded to (Module 1 → 2 → 3) | 16 / 20 |
| Playbook actions auto-executed | 82.5% |
| Actions correctly escalated to human approval | 17.5% |
| Compliance audit | **✅ 0 violations** — no high-blast-radius action ever auto-executed without approval |
| Manual response baseline (aggregate) | 495 minutes |
| Automated response time (aggregate) | 1.58 minutes |

MITRE-tactic-mapped playbooks cover **100% of the 15 ATT&CK tactics**, each action tagged with a blast-radius score; actions scoring ≥4 (e.g. isolating an endpoint, revoking credentials) are **never** auto-executed — they're queued for human sign-off, matching the problem statement's explicit requirement for escalation gates.

Full evaluation: [`incident-response-orchestrator/full_pipeline_evaluation_summary.json`](incident-response-orchestrator/full_pipeline_evaluation_summary.json)

### Module 4 — Vulnerability Prioritisation (real NVD data: 120,875 CVEs, 2015+)

| Metric | Result |
|---|---|
| CVEs in working corpus (merged CVSS-BT + descriptions) | 120,875 |
| CVEs with confirmed active exploitation (CISA KEV) | 840 |
| CNI assets in simulated inventory | 12 (mixed IT/OT: PLCs, SCADA, VPN gateway, DB, etc.) |
| Asset-vulnerability pairs identified via TF-IDF matching | 60 |
| Top-10 overlap: contextualized vs naive CVSS-only ranking | 7/10 |
| Actively-exploited CVEs naive ranking would miss from top-10 | 1 |

**Why this matters:** the contextualized risk score combines CVSS-BT severity (40%), EPSS exploitation probability (25%), CISA KEV active-exploitation status (20%), and asset criticality/network zone (15%) — directly implementing the problem statement's ask to "contextualise exploitability given the specific network topology" rather than just sorting by a generic severity number. The comparison against naive CVSS-only ranking is shown explicitly, not just asserted.

Full evaluation: [`vulnerability-prioritization/vulnerability_prioritization_summary.json`](vulnerability-prioritization/vulnerability_prioritization_summary.json), [`vulnerability-prioritization/remediation_queue.csv`](vulnerability-prioritization/remediation_queue.csv)

---

## 🛠️ Tech Stack

- **ML/Data:** Python, pandas, scikit-learn (Isolation Forest, TF-IDF), NumPy
- **Threat Intelligence:** MITRE ATT&CK STIX 2.1 Enterprise dataset
- **Visualization:** matplotlib, seaborn
- **Dashboard:** *(planned)* Streamlit / React
- **Datasets:** NSL-KDD (network intrusion), MITRE ATT&CK Enterprise (threat framework)

---

## 📁 Project Structure

```
cyber-sentinel-cni/
├── README.md
├── docs/
│   └── SCOPE.md                      # Full scope, success criteria, judging alignment
├── data/
│   ├── nsl-kdd/                      # NSL-KDD train/test datasets
│   └── mitre-cti/                    # MITRE ATT&CK Enterprise STIX bundle
├── anomaly-detection/                # Module 1
│   ├── preprocess.py                 # Data loading + feature encoding
│   ├── anomaly_model.py              # Isolation Forest + real-time scoring
│   ├── advanced_evaluation.py        # IF vs LOF comparison, per-category breakdown
│   ├── rigorous_evaluation.py        # Statistical baseline, ensemble, ROC-AUC, tuning
│   └── *.png / *.json                # Visualizations + saved metrics
├── attribution-agent/                # Module 2
│   ├── mitre_parser.py               # STIX bundle parser
│   ├── attribution_agent.py          # Hybrid RAG retrieval engine
│   ├── pipeline_bridge.py            # Connects Module 1 → Module 2
│   ├── rigorous_evaluation.py        # Retrieval accuracy + campaign narrative builder
│   └── *.json                        # Evaluation results
├── incident-response-orchestrator/   # Module 3
│   ├── playbooks.py                  # MITRE-tactic-mapped response actions + blast radius
│   ├── orchestrator.py               # Core engine: auto-execute vs escalate, audit trail
│   ├── full_pipeline_evaluation.py   # Full Module1->2->3 evaluation + compliance audit
│   └── *.json                        # Audit trail + evaluation results
├── vulnerability-prioritization/     # Module 4
│   ├── cve_loader.py                 # Merges CVSS-BT + descriptions (120K+ real CVEs)
│   ├── asset_matcher.py              # 12-asset CNI inventory + TF-IDF CVE matching
│   ├── risk_ranking.py               # Contextualized scoring + naive-vs-context comparison
│   └── remediation_queue.csv         # Full ranked output
├── digital-twin/                     # Module 5 (planned)
└── frontend/                         # Unified dashboard (planned)
```

---

## 🚀 Getting Started

```bash
git clone https://github.com/raghav-marda/cyber-sentinel-cni.git
cd cyber-sentinel-cni

# Module 1 — Anomaly Detection
cd anomaly-detection
pip install pandas scikit-learn numpy matplotlib seaborn joblib
python3 preprocess.py           # verify data loads correctly
python3 anomaly_model.py        # train + evaluate model
python3 rigorous_evaluation.py  # full rigorous evaluation with ensemble

# Module 2 — APT Attribution
cd ../attribution-agent
python3 mitre_parser.py         # verify MITRE data parses correctly
python3 attribution_agent.py    # run example attributions
python3 pipeline_bridge.py      # test full Module1 -> Module2 pipeline
python3 rigorous_evaluation.py  # retrieval accuracy + campaign narrative demo

# Module 3 — Incident Response Orchestrator
cd ../incident-response-orchestrator
python3 playbooks.py                  # verify playbook coverage (100% of MITRE tactics)
python3 orchestrator.py               # simulate response to 3 sample incidents
python3 full_pipeline_evaluation.py   # full Module1->2->3 evaluation + compliance audit

# Module 4 — Vulnerability Prioritisation
cd ../vulnerability-prioritization
pip install pyarrow
python3 cve_loader.py       # merge CVSS-BT + CVE descriptions (~2 min, large files)
python3 asset_matcher.py    # match CNI assets against CVE corpus
python3 risk_ranking.py     # generate contextualized remediation queue
```

---

## 💾 Datasets

- **[NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)** — Labelled network intrusion dataset (125,973 train / 22,544 test records), an improved version of the classic KDD Cup 99 dataset
- **[MITRE ATT&CK](https://attack.mitre.org/)** — Enterprise Matrix, STIX 2.1 format: 697 active techniques, 189 threat groups, 268 mitigations, 21,000+ relationships
- **[CVSS-BT](https://github.com/t0sche/cvss-bt)** + **NVD CVE descriptions** — 120,875 real CVEs (2015+) enriched with EPSS exploitation probability and CISA KEV active-exploitation status

---

## 🗺️ Roadmap

- [x] Module 1: Behavioural Anomaly Detection (ensemble model, rigorously evaluated)
- [x] Module 2: APT Attribution Agent (hybrid RAG, quantitatively evaluated)
- [x] Module 3: Autonomous Incident Response Orchestrator (MITRE-mapped playbooks, escalation gates, 100% compliance audit)
- [x] Module 4: Vulnerability Prioritisation (real NVD data, contextualized risk scoring)
- [ ] Module 5: Cyber Resilience Digital Twin (attack-path simulation panel)
- [ ] Unified dashboard integrating all 5 modules
- [ ] Improve R2L/U2R detection via supervised fine-tuning on labelled subsets
- [ ] Upgrade retrieval from TF-IDF to semantic embeddings (production enhancement)

---

## 👤 Author

**Raghav Marda** — Solo builder, Amity University Mumbai, Google Student Ambassador 2026

*Last updated: Day 7 of build (see commit history for detailed timeline)*
