"""
CloudShield Correlation Engine
Merges CVE + policy findings, normalizes severity, deduplicates,
and applies cross-source correlation rules.
"""


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEVERITY_NAMES = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNKNOWN"}


def normalize_severity(severity_str):
    """Normalize severity string to standard enum."""
    return severity_str.upper() if severity_str.upper() in SEVERITY_ORDER else "UNKNOWN"


def escalate_severity(severity, levels=1):
    """Escalate severity by N tiers, capping at CRITICAL."""
    current = SEVERITY_ORDER.get(severity, 0)
    escalated = min(current + levels, 4)
    return SEVERITY_NAMES.get(escalated, "UNKNOWN")


def correlate(cve_findings, policy_findings):
    """
    Merge, normalize, deduplicate, and cross-correlate findings.
    
    Args:
        cve_findings: list of CVE findings from scanner
        policy_findings: list of policy findings from policy engine
    
    Returns:
        list of all findings (original + correlated)
    """
    cve_findings = cve_findings or []
    policy_findings = policy_findings or []

    # Step 1: Normalize severity on all findings
    all_findings = []

    for f in cve_findings:
        f = dict(f)  # copy to avoid mutation
        f["severity"] = normalize_severity(f.get("severity", "UNKNOWN"))
        all_findings.append(f)

    for f in policy_findings:
        f = dict(f)
        f["severity"] = normalize_severity(f.get("severity", "UNKNOWN"))
        all_findings.append(f)

    # Step 2: Deduplicate by (source, id)
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get("source", ""), f.get("id", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Step 3: Apply cross-source correlation rules
    correlated = _apply_correlation_rules(cve_findings, policy_findings)
    deduped.extend(correlated)

    return deduped


def _apply_correlation_rules(cve_findings, policy_findings):
    """
    Apply rule-based cross-source correlation.
    Returns new synthetic findings.
    """
    correlated = []
    correlation_id = 0

    # ── Rule 1: Vulnerable Container + Exposed Resource ──
    # If a HIGH+ CVE exists AND a policy violation exposes the workload
    # (public S3, open access), escalate severity by +1 tier
    high_cves = [f for f in cve_findings
                 if SEVERITY_ORDER.get(normalize_severity(f.get("severity", "")), 0) >= 3]

    exposure_policies = [f for f in policy_findings
                         if any(kw in f.get("message", "").lower()
                                for kw in ["public", "public-read", "open", "unrestricted"])]

    if high_cves and exposure_policies:
        # Find the most severe CVE
        worst_cve = max(high_cves,
                        key=lambda f: SEVERITY_ORDER.get(normalize_severity(f.get("severity", "")), 0))
        worst_exposure = exposure_policies[0]

        escalated = escalate_severity(normalize_severity(worst_cve.get("severity", "HIGH")))
        correlation_id += 1
        correlated.append({
            "id": f"CORR-EXPOSED-VULN-{correlation_id}",
            "source": "correlation",
            "type": "CORRELATED",
            "severity": escalated,
            "correlation_rule": "exposed_vulnerability",
            "source_finding_ids": [worst_cve.get("id", ""), worst_exposure.get("id", "")],
            "title": "High-Severity CVE in Publicly Exposed Workload",
            "description": (
                f"Critical vulnerability '{worst_cve.get('id', '')}' in package "
                f"'{worst_cve.get('package', 'unknown')}' is running in an environment "
                f"with public exposure: {worst_exposure.get('message', '')}. "
                f"This combination significantly increases exploitation risk."
            ),
            "message": (
                f"Vulnerability {worst_cve.get('id', '')} ({worst_cve.get('severity', '')}) "
                f"combined with exposed resource creates elevated risk"
            ),
        })

    # ── Rule 2: Privileged Container + Weak IAM ──
    # If container runs privileged/root AND IAM wildcard exists → CRITICAL
    privileged_policies = [f for f in policy_findings
                           if any(kw in f.get("message", "").lower()
                                  for kw in ["privileged mode", "runs as root"])]

    iam_wildcard_policies = [f for f in policy_findings
                              if "wildcard" in f.get("message", "").lower()
                              or "'*'" in f.get("message", "")]

    if privileged_policies and iam_wildcard_policies:
        priv = privileged_policies[0]
        iam = iam_wildcard_policies[0]

        correlation_id += 1
        correlated.append({
            "id": f"CORR-PRIV-ESCALATION-{correlation_id}",
            "source": "correlation",
            "type": "CORRELATED",
            "severity": "CRITICAL",
            "correlation_rule": "privilege_escalation_risk",
            "source_finding_ids": [priv.get("id", ""), iam.get("id", "")],
            "title": "Privileged Container with Wildcard IAM Permissions",
            "description": (
                f"Container running with elevated privileges ({priv.get('message', '')}) "
                f"combined with overly permissive IAM policy ({iam.get('message', '')}). "
                f"This creates a privilege escalation path where a compromised container "
                f"could gain unrestricted cloud access."
            ),
            "message": (
                f"Privileged container + wildcard IAM = critical privilege escalation risk"
            ),
        })

    return correlated


def get_correlation_summary(findings):
    """Return a summary of correlated findings."""
    total = len(findings)
    by_source = {"trivy": 0, "opa": 0, "correlation": 0}
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for f in findings:
        src = f.get("source", "unknown")
        if src in by_source:
            by_source[src] += 1

        sev = f.get("severity", "UNKNOWN")
        if sev in by_severity:
            by_severity[sev] += 1

    return {
        "total_findings": total,
        "by_source": by_source,
        "by_severity": by_severity,
        "correlated_count": by_source.get("correlation", 0),
    }
