# Scope Lock — PS 7: AI-Driven Cyber Resilience for Critical National Infrastructure

**Locked on:** July 3, 2026 | **Deadline:** July 19, 2026 | **Solo build**

# Scope Lock — PS 7: AI-Driven Cyber Resilience for Critical National Infrastructure

**Locked on:** July 3, 2026 | **Deadline:** July 19, 2026 | **Solo build**
**Updated:** Full coverage of all 5 "What You May Build" points, tiered by depth (see below)

## Coverage strategy: ALL 5 official points covered, depth tiered for solo/15-day feasibility

### 🟢 TIER 1 — Full build (real ML/AI, this is where technical depth comes from)

**1. Behavioural Anomaly Detection Engine**
- Ingests network traffic data (NSL-KDD), builds behavioural baseline, scores deviations in real time
- Tech: Python, pandas, scikit-learn (Isolation Forest / One-Class SVM), NSL-KDD dataset
- Output: anomaly score + flagged events with context + measurable precision/recall

**2. APT Campaign Attribution & Prediction Agent**
- Maps flagged anomalies to MITRE ATT&CK tactics/techniques via RAG
- Tech: MITRE ATT&CK STIX data, ChromaDB embeddings, Claude API for reasoning
- Output: technique ID + confidence + recommended defensive action

### 🟡 TIER 2 — Functional mock (real logic, simplified data/integration — still live & demo-able)

**3. Autonomous Incident Response Orchestrator**
- Rule-based playbook engine: pre-defined containment actions (isolate endpoint, alert, log, snapshot) triggered automatically when anomaly score crosses a defined threshold
- Not a real SOAR/live system integration — but the orchestration decision logic runs live in the demo

**4. Government Infrastructure Vulnerability Prioritisation**
- Risk-ranking script using a static/sample CVE dataset (public NVD sample) + basic exploitability scoring logic
- Not a live CVE feed — but shows the prioritization concept working end-to-end

### 🟠 TIER 3 — Visual/conceptual (shown in dashboard + deck, not a full simulation engine)

**5. Cyber Resilience Digital Twin**
- Simple architecture visualization panel in the dashboard with a "what-if" toggle for 1-2 attack path scenarios
- Positioned honestly as a conceptual preview of the full digital twin vision

## Integration — the unified demo
Single dashboard (Streamlit or lightweight React) showing the full pipeline:
raw event → anomaly flagged (Tier 1) → MITRE attribution (Tier 1) → auto-response triggered (Tier 2) → vulnerability priority shown (Tier 2) → digital twin view (Tier 3)

## Why this scope
- Every official "What You May Build" bullet is represented and demo-able — nothing skipped
- Tier 1 modules carry real technical weight (Technical Excellence judging criterion)
- Tier 2/3 modules demonstrate full-platform vision and completeness (Innovation + Business Impact)
- Realistic for solo + beginner + 15 days — avoids the failure mode of 5 shallow/broken modules

## Success criteria for prototype
1. Tier 1: Model correctly flags known-anomalous traffic (measurable precision/recall on held-out set); attribution agent maps 5-10 distinct attack patterns to correct MITRE techniques with citations
2. Tier 2: Orchestrator visibly triggers correct playbook action live during demo; vulnerability ranking produces a sensible priority order on sample data
3. Tier 3: Digital twin panel renders and responds to at least one what-if toggle
4. Full pipeline runs live, end-to-end, without crashing for the 3-4 min demo video
