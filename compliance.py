"""
CloudShield Compliance Mapper
Maps findings to NIST 800-53, ISO 27001, and HIPAA controls.
Uses local JSON mapping — no external APIs.
"""

import json
import os

_MAPPINGS_CACHE = None


def _load_mappings():
    global _MAPPINGS_CACHE
    if _MAPPINGS_CACHE is not None:
        return _MAPPINGS_CACHE
    mappings_path = os.path.join(os.path.dirname(__file__), "compliance_data", "mappings.json")
    try:
        with open(mappings_path, "r", encoding="utf-8") as f:
            _MAPPINGS_CACHE = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[Compliance] Warning: Could not load mappings: {e}")
        _MAPPINGS_CACHE = {"cve_to_compliance": {}, "policy_to_compliance": {}, "correlated_to_compliance": {}}
    return _MAPPINGS_CACHE


def _get_policy_type(finding):
    """Derive policy type key from finding message/rule for compliance lookup."""
    msg = finding.get("message", "").lower()
    if "public" in msg and "s3" in msg: return "s3_public_access"
    if "wildcard" in msg or "'*'" in msg: return "iam_wildcard"
    if "encryption" in msg: return "encryption_disabled"
    if "logging" in msg or "cloudtrail" in msg: return "logging_disabled"
    if "mfa" in msg: return "mfa_not_required"
    if "privileged" in msg: return "privileged_container"
    if "root" in msg: return "root_container"
    return None


def map_compliance(findings):
    """
    Map each finding to compliance framework controls.
    Returns findings enriched with compliance data.
    """
    mappings = _load_mappings()
    enriched = []

    for f in findings:
        f = dict(f)  # copy
        source = f.get("source", "")
        severity = f.get("severity", "UNKNOWN")

        compliance = {"nist": [], "iso27001": [], "hipaa": []}

        if source == "trivy":
            key = f"CVE_{severity}"
            cve_map = mappings.get("cve_to_compliance", {}).get(key, {})
            compliance["nist"] = cve_map.get("nist", [])
            compliance["iso27001"] = cve_map.get("iso27001", [])
            compliance["hipaa"] = cve_map.get("hipaa", [])

        elif source == "opa":
            policy_type = _get_policy_type(f)
            if policy_type:
                pol_map = mappings.get("policy_to_compliance", {}).get(policy_type, {})
                compliance["nist"] = pol_map.get("nist", [])
                compliance["iso27001"] = pol_map.get("iso27001", [])
                compliance["hipaa"] = pol_map.get("hipaa", [])

        elif source == "correlation":
            rule = f.get("correlation_rule", "")
            corr_map = mappings.get("correlated_to_compliance", {}).get(rule, {})
            compliance["nist"] = corr_map.get("nist", [])
            compliance["iso27001"] = corr_map.get("iso27001", [])
            compliance["hipaa"] = corr_map.get("hipaa", [])

        f["compliance"] = compliance
        enriched.append(f)

    return enriched


def get_compliance_summary(findings):
    """Summarize compliance impact across all findings."""
    all_nist, all_iso, all_hipaa = set(), set(), set()
    for f in findings:
        c = f.get("compliance", {})
        all_nist.update(c.get("nist", []))
        all_iso.update(c.get("iso27001", []))
        all_hipaa.update(c.get("hipaa", []))
    return {
        "frameworks_impacted": sum(1 for s in [all_nist, all_iso, all_hipaa] if s),
        "nist_controls": sorted(all_nist),
        "iso27001_clauses": sorted(all_iso),
        "hipaa_safeguards": sorted(all_hipaa),
    }
