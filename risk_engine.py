"""
CloudShield Risk Engine
Separated CVE/Policy/Correlated stream scoring with weighted aggregation.
Deterministic — no AI/LLM.
"""


SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

# Stream weights — correlated findings carry highest signal
STREAM_WEIGHTS = {
    "trivy": 0.45,
    "opa": 0.30,
    "correlation": 0.25,
}


def compute_risk_scores(findings):
    """
    Compute risk scores by separating findings into independent streams,
    scoring each, then producing a weighted aggregate.
    
    Returns:
        dict with final_score, category, and per-stream breakdown
    """
    if not findings:
        return {
            "final_score": 0.0,
            "category": "LOW",
            "cve_score": 0.0,
            "policy_score": 0.0,
            "correlated_score": 0.0,
            "finding_count": 0,
            "per_finding_scores": [],
        }

    # Step 1: Separate findings by source stream
    streams = {"trivy": [], "opa": [], "correlation": []}
    for f in findings:
        source = f.get("source", "unknown")
        if source in streams:
            streams[source].append(f)

    # Step 2: Score each stream independently
    stream_scores = {}
    for stream_name, stream_findings in streams.items():
        if stream_findings:
            scores = [SEVERITY_MAP.get(f.get("severity", "UNKNOWN"), 0) for f in stream_findings]
            stream_scores[stream_name] = sum(scores) / len(scores)
        else:
            stream_scores[stream_name] = 0.0

    cve_score = stream_scores.get("trivy", 0.0)
    policy_score = stream_scores.get("opa", 0.0)
    correlated_score = stream_scores.get("correlation", 0.0)

    # Step 3: Weighted aggregate — only count streams that have findings
    active_streams = {k: v for k, v in stream_scores.items() if streams.get(k)}
    if active_streams:
        # Redistribute weights among active streams proportionally
        total_weight = sum(STREAM_WEIGHTS[k] for k in active_streams)
        final_score = sum(
            (STREAM_WEIGHTS[k] / total_weight) * v
            for k, v in active_streams.items()
        )
    else:
        final_score = 0.0

    # Step 4: Per-finding scores for detailed reporting
    per_finding_scores = []
    for f in findings:
        severity_val = SEVERITY_MAP.get(f.get("severity", "UNKNOWN"), 0)
        per_finding_scores.append({
            "id": f.get("id", ""),
            "source": f.get("source", ""),
            "severity": f.get("severity", "UNKNOWN"),
            "score": float(severity_val),
        })

    return {
        "final_score": round(final_score, 2),
        "category": _categorize_score(final_score),
        "cve_score": round(cve_score, 2),
        "policy_score": round(policy_score, 2),
        "correlated_score": round(correlated_score, 2),
        "finding_count": len(findings),
        "per_finding_scores": per_finding_scores,
    }


def _categorize_score(score):
    """Map numeric score to risk category."""
    if score > 3.5:
        return "CRITICAL"
    elif score >= 2.5:
        return "HIGH"
    elif score >= 1.5:
        return "MEDIUM"
    else:
        return "LOW"


def get_risk_summary(risk_result):
    """Return a formatted risk summary string."""
    return (
        f"Risk Score: {risk_result['final_score']} ({risk_result['category']})\n"
        f"  CVE Stream:        {risk_result['cve_score']}\n"
        f"  Policy Stream:     {risk_result['policy_score']}\n"
        f"  Correlated Stream: {risk_result['correlated_score']}\n"
        f"  Total Findings:    {risk_result['finding_count']}"
    )
