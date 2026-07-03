# AI-Driven Cyber Resilience for Critical National Infrastructure
### ET AI Hackathon 2026 — Problem Statement 7

## Overview
A behavioural intelligence platform that detects network anomalies without relying on known malware signatures, and maps confirmed threats to MITRE ATT&CK techniques to generate actionable defensive recommendations — compressing detection time from weeks to minutes.

## What this prototype does
1. **Anomaly Detection Engine** — flags deviations from normal network behaviour using unsupervised ML
2. **APT Attribution Agent** — maps flagged anomalies to MITRE ATT&CK tactics/techniques using RAG, and suggests next-stage predictions + defensive actions
3. **Unified Dashboard** — end-to-end demo: raw event → anomaly flag → MITRE attribution → recommended action

See `docs/SCOPE.md` for exact build boundaries and what's intentionally out of scope for this prototype (roadmapped instead).

## Repo structure
```
anomaly-detection/   # Module 1: ML model + preprocessing
attribution-agent/   # Module 2: RAG + MITRE ATT&CK mapping
frontend/            # Dashboard connecting both modules
data/                # Datasets (NSL-KDD/CICIDS2017 + MITRE ATT&CK STIX)
docs/                # Scope, architecture diagram, deliverables
```

## Datasets (already downloaded, in `data/`)
- `data/nsl-kdd/` — NSL-KDD network intrusion dataset (train + test, labelled normal/attack traffic) for Module 1
- `data/mitre-cti/enterprise-attack/enterprise-attack.json` — Full MITRE ATT&CK Enterprise STIX bundle (tactics, techniques, relationships) for Module 2

## Status
🚧 Day 1 — scope locked, structure initialized, datasets downloaded. Build in progress.

## Team
Raghav — Solo builder, Amity University Mumbai
