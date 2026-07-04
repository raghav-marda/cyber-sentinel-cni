"""
Pipeline Bridge: Anomaly Detection (Module 1) -> APT Attribution (Module 2)

Converts a raw flagged NSL-KDD network event into a natural-language
behaviour description using rule-based heuristics on key traffic
indicators, then feeds it into the AttributionAgent for MITRE ATT&CK
mapping. This is what makes the two modules work together as ONE
unified pipeline instead of two disconnected demos.
"""

import sys
sys.path.append("../anomaly-detection")


def event_to_description(event: dict) -> str:
    """
    Rule-based translation of raw NSL-KDD traffic features into a
    human-readable behaviour description, suitable as input to the
    attribution agent's retrieval step.
    """
    clues = []

    service = event.get("service", "")
    flag = event.get("flag", "")
    count = event.get("count", 0)
    srv_count = event.get("srv_count", 0)
    num_failed_logins = event.get("num_failed_logins", 0)
    logged_in = event.get("logged_in", 0)
    root_shell = event.get("root_shell", 0)
    num_compromised = event.get("num_compromised", 0)
    dst_bytes = event.get("dst_bytes", 0)
    src_bytes = event.get("src_bytes", 0)
    serror_rate = event.get("serror_rate", 0)

    # High connection count to many different services in short time -> scanning
    if count > 100 and srv_count < 10:
        clues.append("attacker scanning multiple ports and services across the network to identify open services")

    # SYN flag with no follow-up (S0) + high count -> SYN flood / DoS
    if flag == "S0" and count > 50:
        clues.append("high volume of half-open TCP connections consistent with a SYN flood denial-of-service pattern")

    # Failed logins followed by successful login
    if num_failed_logins > 0 and logged_in == 1:
        clues.append("repeated failed login attempts followed by a successful login using valid credentials")

    # Root shell obtained
    if root_shell == 1:
        clues.append("privilege escalation observed — root shell access obtained on the host")

    # Compromised indicators
    if num_compromised > 0:
        clues.append("indicators of host compromise detected in system state")

    # Large outbound data transfer
    if dst_bytes > 5000 and src_bytes < 500:
        clues.append("unusual outbound data transfer of significant volume to an external destination")

    # High SYN error rate -> reconnaissance/scanning
    if serror_rate > 0.5:
        clues.append("high rate of connection errors consistent with reconnaissance or scanning activity")

    if not clues:
        clues.append(f"anomalous {service} traffic with irregular connection pattern (flag={flag})")

    return "; ".join(clues)


def run_full_pipeline(agent, anomaly_result: dict, raw_event: dict):
    """
    Full pipeline: anomaly result + raw event -> description -> MITRE attribution.
    anomaly_result: output from check_single_event() in Module 1
    raw_event: the raw feature dict that was scored
    """
    if not anomaly_result["is_anomaly"]:
        return {
            "status": "no_action",
            "reason": "Event classified as normal behaviour, no attribution needed"
        }

    description = event_to_description(raw_event)
    attribution = agent.attribute(description, top_k=3)

    return {
        "status": "anomaly_attributed",
        "anomaly_score": anomaly_result["anomaly_score"],
        "severity": anomaly_result["severity"],
        "generated_description": description,
        "mitre_attribution": attribution
    }


if __name__ == "__main__":
    import joblib
    from attribution_agent import AttributionAgent
    from anomaly_model import check_single_event
    from preprocess import COLUMN_NAMES, load_data

    print("Loading Module 1 (anomaly model) + Module 2 (attribution agent)...")
    model = joblib.load("../anomaly-detection/anomaly_model.pkl")
    scaler = joblib.load("../anomaly-detection/scaler.pkl")
    encoders = joblib.load("../anomaly-detection/encoders.pkl")
    feature_cols = [c for c in COLUMN_NAMES if c not in ("label", "difficulty")]
    agent = AttributionAgent()

    train_df, test_df = load_data("../data/nsl-kdd/KDDTrain+.txt", "../data/nsl-kdd/KDDTest+.txt")

    print("\n" + "=" * 90)
    print("FULL PIPELINE TEST: real attack events from test set -> anomaly detection -> MITRE attribution")
    print("=" * 90)

    # Pull a few real attack rows of different types
    for attack_label in ["neptune", "satan", "guess_passwd", "buffer_overflow"]:
        rows = test_df[test_df["label"] == attack_label]
        if len(rows) == 0:
            continue
        row = rows.iloc[0]
        raw_event = row[feature_cols].to_dict()

        anomaly_result = check_single_event(model, scaler, encoders, feature_cols, raw_event)
        pipeline_result = run_full_pipeline(agent, anomaly_result, raw_event)

        print(f"\n--- True label: {attack_label} ---")
        print(f"Anomaly detected: {anomaly_result['is_anomaly']} (severity: {anomaly_result['severity']})")
        if pipeline_result["status"] == "anomaly_attributed":
            print(f"Generated description: {pipeline_result['generated_description']}")
            print("Top MITRE ATT&CK attribution:")
            for a in pipeline_result["mitre_attribution"][:2]:
                print(f"  -> {a['mitre_id']} - {a['name']} (tactics: {a['tactics']})")
        else:
            print("  (Not flagged as anomaly - no attribution triggered)")
