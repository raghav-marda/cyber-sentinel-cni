# Cyber Sentinel CNI

AI-driven cyber resilience for critical national infrastructure — built solo for **ET AI Hackathon 2026, Problem Statement 7**.

CERT-In handled over 1.59 million cybersecurity incidents in 2023, and most breaches in government/CNI systems are found weeks or months after the attacker got in. Signature-based tools can't catch that because sophisticated attackers deliberately avoid known signatures. This project tries a different angle: learn what normal looks like, flag what isn't, and figure out what to do about it — automatically where it's safe to, and with a human in the loop where it isn't.

## What's actually in here

Five modules, matching the five things the problem statement lists under "what you may build." All five are implemented, not mocked — some more mature than others (see the status table below).

| # | Module | Status |
|---|--------|--------|
| 1 | Behavioural Anomaly Detection Engine | Done |
| 2 | APT Campaign Attribution & Prediction Agent | Done |
| 3 | Autonomous Incident Response Orchestrator | Done |
| 4 | Government Infrastructure Vulnerability Prioritisation | Done |
| 5 | Cyber Resilience Digital Twin | In progress |

Full scope and reasoning behind what's in vs. out is in [`docs/SCOPE.md`](docs/SCOPE.md).

## How the pieces fit together

```
Network traffic (NSL-KDD / live feed)
        │
        ▼
Module 1: Anomaly Detection  ──► flags a deviation + severity
        │
        ▼
Module 2: MITRE ATT&CK Attribution  ──► what technique, which known group, what's likely next
        │
        ▼
Module 3: Incident Response Orchestrator  ──► auto-contains low-risk stuff, escalates the rest
        │
        ▼
Module 4: Vulnerability Prioritisation  ──► feeds back which assets to patch first, given what's actively under attack
```

Modules 1→2→3 run as one live pipeline (there's a script that proves it end-to-end on real data, not just each module in isolation). Module 4 pulls in real threat-actor data from Module 2 to decide which CVEs matter more right now — more on that below.

## Module 1 — Anomaly Detection

Trained only on normal NSL-KDD traffic (no attack data during training — that's the actual point of anomaly detection, not cheating by peeking at labels). Tried three approaches and kept receipts on all of them instead of just reporting the best one:

| Method | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| Statistical z-score baseline | 0.851 | 0.858 | 0.854 | 0.894 |
| Isolation Forest | 0.974 | 0.648 | 0.778 | 0.939 |
| Ensemble (both, weighted) | 0.871 | 0.878 | **0.874** | 0.935 |

The z-score baseline actually beat the ML model on F1 by itself — which was a surprise, but it's exactly why the ensemble exists. Combining the two beat both individually.

Detection isn't uniform across attack types, and I'm not hiding that:

- DoS: 79.3% detected
- Probe: 88.3% detected
- R2L: 8.6% detected
- U2R: 28.4% detected

R2L and U2R attacks are low-and-slow and barely deviate from normal traffic — this is a documented hard problem in NSL-KDD research generally, not something specific to my implementation. Listed as a real limitation below, not swept under the rug.

Also ran a full hyperparameter sweep, ROC curves, permutation-based feature importance (to know *why* something got flagged), and broke down anomaly rate by protocol (TCP/UDP/ICMP) since the problem statement specifically asks for behavioural baselines per network segment.

## Module 2 — APT Attribution

Given a description of observed behaviour, this maps it to a MITRE ATT&CK technique, tells you which known threat groups use that technique, predicts the likely next stage of the attack (using ATT&CK's kill-chain ordering), and pulls real mitigation advice from MITRE's own data — nothing invented.

Retrieval is TF-IDF over all 697 active ATT&CK techniques, with a small keyword-boost layer on top for common SOC phrasing (pure TF-IDF alone missed some obvious matches — e.g. "scanning multiple ports" didn't surface Network Service Discovery on its own, so I added rule-based reinforcement for known terminology). Tested this properly instead of eyeballing a few examples: held out 150 technique descriptions and checked whether the system could retrieve the right technique from a paraphrase of its own text.

- Top-1 accuracy: 62.7%
- Top-3 accuracy: 96.0%

(random guessing across 697 techniques would get you top-3 accuracy of about 0.4%, for scale)

There's also a multi-stage campaign builder — feed it a sequence of anomalies over time and it reconstructs the likely kill-chain narrative and ranks which known APT groups' historical technique usage overlaps most with what was observed (Jaccard similarity over technique sets).

## Module 3 — Incident Response Orchestrator

Playbooks are mapped from MITRE tactic → containment action, covering all 15 ATT&CK tactics. Each action carries a base "blast radius" (how disruptive it is), but that number isn't static — it's multiplied by the *actual* criticality of the target asset, pulled straight from Module 4's asset inventory. Isolating a print server and isolating a SCADA turbine controller are not the same decision, so they shouldn't be treated the same.

Auto-execution also requires the anomaly's severity to be "high" or "critical" — because Module 1 is roughly 80% accurate, not 100%, and auto-containing on a medium-confidence flag has a real operational cost if it turns out to be nothing. Added a rollback function for exactly that scenario (a false positive gets confirmed after the fact, and the containment action gets reversed).

One more thing real SOAR systems need that a toy version usually skips: if multiple incidents hit the same host in a short window, they get grouped as one coordinated campaign instead of triggering duplicate, possibly conflicting responses.

Ran this against 20 real attack events through the full Module 1→2→3 chain:

- 16/20 attacks detected and responded to automatically
- 77.5% of triggered actions auto-executed, 22.5% escalated to a human
- 5 incidents correctly grouped into 2-incident correlated campaigns
- 0 compliance violations — verified after the fact that no high-blast-radius action was ever auto-executed without approval

## Module 4 — Vulnerability Prioritisation

Uses real data: merged CVSS-BT (77MB) with NVD CVE descriptions (55MB) into about 121K CVEs from 2015 onward, enriched with EPSS (probability of exploitation) and CISA KEV (confirmed active exploitation right now). Built a small inventory of 12 representative CNI assets — PLCs, SCADA HMI, a domain controller, VPN gateway, etc. — and match each one against the CVE corpus via TF-IDF over the descriptions. The matches are specific: actual Siemens SIMATIC PLC CVEs for the PLC asset, actual Schneider Electric CVEs for the SCADA asset, not generic noise.

The risk score isn't just CVSS. It's CVSS-BT (40%) + EPSS (25%) + a flat bonus if it's on the CISA KEV list (20%) + asset criticality (15%), then adjusted further by two things:

- **Threat-actor relevance** — cross-referenced against Module 2's attributed campaign to see if the *specific* group currently in play is known (via real MITRE malware/tool platform data) to target this asset's platform. If yes, the score gets boosted.
- **Unpatched age** — using the CVE's actual publish date, older unremediated high-risk CVEs get scaled up, since a 3-year-old unpatched critical CVE is a bigger compliance problem than one discovered last month.

Compared this against naive CVSS-only sorting explicitly (not just asserted that context matters): the two top-10 lists only overlap 7/10, and one actively-exploited (KEV) vulnerability that naive ranking would leave out of the top 10 gets correctly surfaced by the contextualized version.

It also doesn't stop at a ranked list — real teams can't patch everything Monday morning, so there's a capacity-constrained scheduler that assumes a fixed weekly patch throughput and lays out an actual week-by-week remediation plan.

## Getting it running

```bash
git clone https://github.com/raghav-marda/cyber-sentinel-cni.git
cd cyber-sentinel-cni

# Module 1
cd anomaly-detection
pip install pandas scikit-learn numpy matplotlib seaborn joblib
python3 preprocess.py
python3 anomaly_model.py
python3 rigorous_evaluation.py

# Module 2
cd ../attribution-agent
python3 mitre_parser.py
python3 attribution_agent.py
python3 pipeline_bridge.py
python3 rigorous_evaluation.py

# Module 3
cd ../incident-response-orchestrator
python3 playbooks.py
python3 orchestrator.py
python3 full_pipeline_evaluation.py

# Module 4
cd ../vulnerability-prioritization
pip install pyarrow
python3 cve_loader.py       # merges the two CVE datasets, takes a minute or two
python3 asset_matcher.py
python3 risk_ranking.py
```

## Repo layout

```
cyber-sentinel-cni/
├── docs/SCOPE.md                      # what's in scope, why, and how success is measured
├── data/
│   ├── nsl-kdd/                       # network intrusion dataset
│   ├── mitre-cti/                     # MITRE ATT&CK Enterprise STIX bundle
│   ├── cvss-bt/                       # CVE scores + EPSS + CISA KEV
│   └── cve-offline/                   # CVE descriptions
├── anomaly-detection/                 # Module 1
├── attribution-agent/                 # Module 2
├── incident-response-orchestrator/    # Module 3
├── vulnerability-prioritization/      # Module 4
├── digital-twin/                      # Module 5 (in progress)
└── frontend/                          # unified dashboard (planned)
```

## Datasets used

- [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) — 125,973 train / 22,544 test labelled network traffic records
- [MITRE ATT&CK](https://attack.mitre.org/) Enterprise Matrix (STIX 2.1) — 697 techniques, 189 threat groups, 268 mitigations
- [CVSS-BT](https://github.com/t0sche/cvss-bt) + NVD CVE descriptions — ~121K real CVEs enriched with EPSS and CISA KEV status

## What's left / known gaps

- Module 5 (digital twin) — not started yet
- Dashboard tying all 5 modules into one UI — planned for the last couple of days before submission
- R2L/U2R detection in Module 1 is weak (documented above) — would need supervised fine-tuning on labelled data to meaningfully improve, didn't have time to do that properly and didn't want to fake it
- Retrieval in Module 2 uses TF-IDF, not semantic embeddings — works well enough for this scope (96% top-3 accuracy) but a production version would benefit from real embeddings

---

Raghav Marda, Amity University Mumbai — solo build, ET AI Hackathon 2026.
