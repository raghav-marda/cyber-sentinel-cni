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
4. Auto-contains low-risk incidents while escalating high-risk ones to a human, with full auditability
5. Prioritizes vulnerability remediation using real CVE data contextualized by asset criticality and active threat-actor targeting
6. Simulates attack paths and security-investment impact on a digital twin — without touching live systems

---

## 🏗️ Architecture

```
                    ┌─────────────────────────┐
                    │   Raw Network Traffic    │
                    │   (NSL-KDD / live feed)  │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   MODULE 1                 │
                    │   Behavioural Anomaly      │
                    │   Detection Engine         │
                    │   (Ensemble: Statistical   │
                    │   Z-score + Isolation      │
                    │   Forest)                  │
                    └────────────┬─────────────┘
                                 │ flagged anomaly + severity
                    ┌────────────▼─────────────┐
                    │   Pipeline Bridge           │
                    │   (event → NL description)  │
                    └────────────┬─────────────┘
                                 │ behaviour description
                    ┌────────────▼─────────────┐
                    │   MODULE 2                  │
                    │   APT Attribution Agent      │
                    │   (Hybrid RAG: TF-IDF +      │
                    │   keyword rules over MITRE   │
                    │   ATT&CK, 697 techniques)     │
                    └────────────┬─────────────┘
                                 │ technique + tactics + threat group
                    ┌────────────▼─────────────┐
                    │   MODULE 3                   │
                    │   Incident Response           │
                    │   Orchestrator (dynamic       │
                    │   blast radius, escalation     │
                    │   gates, rollback, audit)      │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐        ┌───────────────────────┐
                    │   MODULE 4                   │◄─────►│   MODULE 5              │
                    │   Vulnerability Prioritisation│        │   Cyber Resilience      │
                    │   (real NVD data, threat-actor │        │   Digital Twin           │
                    │   context, capacity scheduling) │        │   (attack-path sim,      │
                    └───────────────────────────────┘        │   investment impact)     │
                                                              └───────────────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │   Unified Dashboard         │
                    └───────────────────────────┘
```

Modules 1→2→3 run as a proven live pipeline. Modules 4 and 5 cross-reference each other's real data (asset criticality, threat-actor context, vulnerability scores) rather than operating in isolation.

---

## 📦 Modules & Progress

| # | Module | Status | Depth |
|---|--------|--------|-------|
| 1 | **Behavioural Anomaly Detection Engine** | ✅ Complete | Ensemble model, statistical baseline comparison, rigorous evaluation |
| 2 | **APT Campaign Attribution & Prediction Agent** | ✅ Complete | Hybrid RAG, quantitatively evaluated, campaign narrative builder |
| 3 | **Autonomous Incident Response Orchestrator** | ✅ Complete | Dynamic blast radius, confidence gating, rollback, campaign correlation |
| 4 | **Government Infrastructure Vulnerability Prioritisation** | ✅ Complete | Real NVD data, threat-actor context, capacity-constrained scheduling |
| 5 | **Cyber Resilience Digital Twin** | ✅ Complete | Attack-path simulation, choke-point analysis, investment impact testing |

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

¹ *R2L/U2R attacks are low-volume and behaviourally subtle — a known, documented challenge in NSL-KDD research. Flagged here transparently as a limitation, not hidden — and it directly drives the risk ranking in Module 5's red-team scenarios (see below).*

### Module 2 — APT Attribution Agent (RAG over MITRE ATT&CK, 697 techniques)

| Metric | Score |
|---|---|
| Top-1 retrieval accuracy | 62.7% |
| Top-3 retrieval accuracy | **96.0%** |
| Techniques / threat groups / mitigations indexed | 697 / 189 / 268 |

*(Evaluated on 150 held-out technique descriptions — random-chance top-3 accuracy would be ~0.4%.)*

### Module 3 — Incident Response Orchestrator (evaluated on 20 real attack events, full pipeline)

| Metric | Result |
|---|---|
| Attacks detected & responded to (Module 1 → 2 → 3) | 16 / 20 |
| Playbook actions auto-executed | 77.5% |
| Actions correctly escalated to human approval | 22.5% |
| Correlated multi-incident campaigns detected | 5 |
| Compliance audit | **✅ 0 violations** |

Blast radius is **dynamic** — computed from the action's base disruption potential × the *real* criticality of the target asset (pulled from Module 4's inventory), and auto-execution additionally requires high/critical detection confidence, accounting for Module 1's ~80% accuracy.

### Module 4 — Vulnerability Prioritisation (real NVD data: 120,875 CVEs, 2015+)

| Metric | Result |
|---|---|
| CVEs with confirmed active exploitation (CISA KEV) | 840 |
| Asset-vulnerability pairs matched (12-asset CNI inventory) | 60 |
| Pairs boosted by active threat-actor platform relevance | 25 |
| Top-10 overlap: contextualized vs naive CVSS-only ranking | 7/10 |

Risk score combines CVSS-BT (40%) + EPSS (25%) + CISA KEV (20%) + asset criticality (15%), then adjusted by **threat-actor relevance** (cross-referenced against Module 2's attributed campaign using real MITRE malware-platform data) and **unpatched age** (using real CVE publish dates). Output includes a capacity-constrained 6-week remediation schedule, not just a static list.

### Module 5 — Cyber Resilience Digital Twin

| Scenario | Critical assets reachable from Internet | Avg. exploit cost |
|---|---|---|
| Baseline (current state) | 5 / 5 | 11.68 |
| IT/OT segmentation only | 2 / 5 | 4.48 |
| Patch top-3 CVEs only | 5 / 5 | 14.28 |
| Segmentation + patching combined | 2 / 5 | 10.98 |

**Network segmentation alone blocks 3 of 5 mission-critical assets completely** (PLC, SCADA, RTU become unreachable) — a bigger impact than patching the top-3 highest-risk CVEs, which makes attacks harder but doesn't fully block anything. Red-team scenario testing further shows that phishing/credential-theft scenarios (R2L category) carry the highest *expected undetected risk* — not because they reach the most assets, but because Module 1 only detects 8.6% of R2L attacks. Risk = reachability × (1 − detection probability), and the twin surfaces that explicitly.

---

## 🛠️ Tech Stack

- **ML/Data:** Python, pandas, scikit-learn (Isolation Forest, TF-IDF), NumPy
- **Graph analysis:** NetworkX (attack-path simulation, centrality analysis)
- **Threat Intelligence:** MITRE ATT&CK STIX 2.1 Enterprise dataset, CVSS-BT (EPSS + CISA KEV enrichment), NVD CVE descriptions
- **Visualization:** matplotlib, seaborn
- **Dashboard:** *(planned)* Streamlit / React

---

## 📁 Project Structure

```
cyber-sentinel-cni/
├── README.md
├── docs/
│   └── SCOPE.md                      # Full scope, success criteria, judging alignment
├── data/
│   ├── nsl-kdd/                      # NSL-KDD train/test datasets
│   ├── mitre-cti/                    # MITRE ATT&CK Enterprise STIX bundle
│   ├── cvss-bt/                      # CVE scores + EPSS + CISA KEV enrichment
│   └── cve-offline/                  # CVE descriptions
├── anomaly-detection/                # Module 1
├── attribution-agent/                # Module 2
├── incident-response-orchestrator/   # Module 3
├── vulnerability-prioritization/     # Module 4
├── digital-twin/                     # Module 5
└── frontend/                         # Unified dashboard (Streamlit, app.py)
```

---

## 🚀 Getting Started

```bash
git clone https://github.com/raghav-marda/cyber-sentinel-cni.git
cd cyber-sentinel-cni

# Module 1 — Anomaly Detection
cd anomaly-detection
pip install pandas scikit-learn numpy matplotlib seaborn joblib
python3 preprocess.py
python3 anomaly_model.py
python3 rigorous_evaluation.py

# Module 2 — APT Attribution
cd ../attribution-agent
python3 mitre_parser.py
python3 attribution_agent.py
python3 pipeline_bridge.py
python3 rigorous_evaluation.py

# Module 3 — Incident Response Orchestrator
cd ../incident-response-orchestrator
python3 playbooks.py
python3 orchestrator.py
python3 full_pipeline_evaluation.py

# Module 4 — Vulnerability Prioritisation
cd ../vulnerability-prioritization
pip install pyarrow
python3 cve_loader.py
python3 asset_matcher.py
python3 risk_ranking.py

# Module 5 — Cyber Resilience Digital Twin
cd ../digital-twin
pip install networkx
python3 topology.py
python3 attack_path_simulator.py
python3 investment_impact.py
python3 red_team_scenarios.py
python3 visualize_topology.py

# Unified Dashboard (run after all 5 modules have been executed at least once,
# so their result files exist for the dashboard to load)
cd ../frontend
pip install -r requirements.txt
streamlit run app.py
```

---

## 💾 Datasets

- **[NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)** — Labelled network intrusion dataset (125,973 train / 22,544 test records)
- **[MITRE ATT&CK](https://attack.mitre.org/)** — Enterprise Matrix, STIX 2.1 format: 697 active techniques, 189 threat groups, 268 mitigations
- **[CVSS-BT](https://github.com/t0sche/cvss-bt)** + NVD CVE descriptions — 120,875 real CVEs (2015+) enriched with EPSS and CISA KEV status

---

## 🗺️ Roadmap

- [x] Module 1: Behavioural Anomaly Detection (ensemble model, rigorously evaluated)
- [x] Module 2: APT Attribution Agent (hybrid RAG, quantitatively evaluated)
- [x] Module 3: Autonomous Incident Response Orchestrator (dynamic blast radius, 100% compliance audit)
- [x] Module 4: Vulnerability Prioritisation (real NVD data, threat-actor context, capacity scheduling)
- [x] Module 5: Cyber Resilience Digital Twin (attack-path simulation, investment impact assessment)
- [x] Unified dashboard integrating all 5 modules (Streamlit)
- [ ] Improve R2L/U2R detection via supervised fine-tuning on labelled subsets
- [ ] Upgrade retrieval from TF-IDF to semantic embeddings (production enhancement)

---

## 👤 Author

**Raghav Marda** — Solo builder, Amity University Mumbai, Google Student Ambassador 2026

*Last updated: Day 8 of build (see commit history for detailed timeline)*
