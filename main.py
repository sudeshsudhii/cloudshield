"""
CloudShield — CLI Orchestrator
Unified Detection and Remediation of Container and Cloud Misconfigurations.

Usage:
    python main.py --config sample_data/bad_aws_config.json
    python main.py --image nginx:1.14 --config sample_data/bad_aws_config.json
    python main.py --trivy-output sample_data/sample_trivy_output.json --config sample_data/bad_aws_config.json
    python main.py --demo
    python main.py --config sample_data/bad_aws_config.json --dashboard
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

from scanner import scan_image, scan_from_file, get_scan_summary
from policy_engine import evaluate_config, get_policy_summary
from correlation import correlate, get_correlation_summary
from risk_engine import compute_risk_scores, get_risk_summary
from remediation import generate_remediations, get_remediation_summary
from compliance import map_compliance, get_compliance_summary

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None
    print("[Warning] tabulate not installed. Using basic table output.", file=sys.stderr)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICIES_DIR = os.path.join(BASE_DIR, "policies")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SAMPLE_DIR = os.path.join(BASE_DIR, "sample_data")


def run_pipeline(image=None, config=None, trivy_output=None):
    """Execute the full CloudShield pipeline. Returns pipeline result dict."""
    log = []
    ts = lambda: datetime.now().strftime("%H:%M:%S")

    # Step 1: Scanner
    t0 = time.time()
    cve_findings = []
    if trivy_output:
        log.append(f"[{ts()}] Scanner — loading from file: {trivy_output}")
        cve_findings = scan_from_file(trivy_output) or []
    elif image:
        log.append(f"[{ts()}] Scanner — scanning image: {image}")
        cve_findings = scan_image(image) or []
    else:
        log.append(f"[{ts()}] Scanner — no image specified, skipping CVE scan")
    scan_time = round(time.time() - t0, 2)

    sev_counts = {}
    for f in cve_findings:
        s = f.get("severity", "UNKNOWN")
        sev_counts[s] = sev_counts.get(s, 0) + 1
    crit_count = sev_counts.get("CRITICAL", 0)
    log.append(f"[{ts()}] ✓ Scanner — {len(cve_findings)} vulnerabilities found ({crit_count} CRITICAL) [{scan_time}s]")

    # Step 2: Policy Engine
    t0 = time.time()
    policy_findings = []
    if config:
        log.append(f"[{ts()}] Policy Engine — evaluating: {config}")
        policy_findings = evaluate_config(config, POLICIES_DIR) or []
    else:
        log.append(f"[{ts()}] Policy Engine — no config specified, skipping")
    policy_time = round(time.time() - t0, 2)

    pol_sev = {}
    for f in policy_findings:
        s = f.get("severity", "UNKNOWN")
        pol_sev[s] = pol_sev.get(s, 0) + 1
    pol_crit = pol_sev.get("CRITICAL", 0)
    log.append(f"[{ts()}] ✓ Policy Engine — {len(policy_findings)} violations ({pol_crit} CRITICAL) [{policy_time}s]")

    # Step 3: Correlation
    t0 = time.time()
    all_findings = correlate(cve_findings, policy_findings)
    corr_count = sum(1 for f in all_findings if f.get("source") == "correlation")
    corr_time = round(time.time() - t0, 2)
    log.append(f"[{ts()}] ✓ Correlation — {corr_count} cross-source findings [{corr_time}s]")

    # Step 4: Risk Scoring
    t0 = time.time()
    risk = compute_risk_scores(all_findings)
    risk_time = round(time.time() - t0, 2)
    log.append(f"[{ts()}] ✓ Risk Scoring — Score: {risk['final_score']} ({risk['category']}) [{risk_time}s]")

    # Step 5: Remediation
    t0 = time.time()
    remediations = generate_remediations(all_findings)
    rem_time = round(time.time() - t0, 2)
    log.append(f"[{ts()}] ✓ Remediation — {len(remediations)} fix actions [{rem_time}s]")

    # Step 6: Compliance
    t0 = time.time()
    enriched = map_compliance(all_findings)
    comp_summary = get_compliance_summary(enriched)
    comp_time = round(time.time() - t0, 2)
    log.append(f"[{ts()}] ✓ Compliance — Mapped to {comp_summary['frameworks_impacted']} frameworks [{comp_time}s]")

    return {
        "timestamp": datetime.now().isoformat(),
        "findings": enriched,
        "risk": risk,
        "remediations": remediations,
        "compliance": comp_summary,
        "scan_summary": get_scan_summary(cve_findings),
        "policy_summary": get_policy_summary(policy_findings),
        "correlation_summary": get_correlation_summary(all_findings),
        "remediation_summary": get_remediation_summary(remediations),
        "execution_log": log,
    }


def print_cli_table(result):
    """Print findings as a formatted CLI table."""
    rows = []
    findings = result.get("findings", [])
    remediations = result.get("remediations", [])

    rem_map = {r["finding_id"]: r for r in remediations}

    for f in findings:
        fid = f.get("id", "")
        rem = rem_map.get(fid, {})
        fix = rem.get("title", "N/A")
        score = next(
            (p["score"] for p in result.get("risk", {}).get("per_finding_scores", []) if p["id"] == fid),
            0
        )
        rows.append([
            fid[:25],
            f.get("type", ""),
            f.get("severity", ""),
            score,
            fix[:45],
        ])

    headers = ["Issue", "Type", "Severity", "Score", "Fix"]

    if tabulate:
        print("\n" + tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        # Basic table fallback
        print("\n" + " | ".join(headers))
        print("-" * 80)
        for row in rows:
            print(" | ".join(str(c) for c in row))

    # Risk summary
    risk = result.get("risk", {})
    print(f"\n{'='*60}")
    print(f"  RISK SCORE: {risk.get('final_score', 0)} — {risk.get('category', 'N/A')}")
    print(f"    CVE Stream:        {risk.get('cve_score', 0)}")
    print(f"    Policy Stream:     {risk.get('policy_score', 0)}")
    print(f"    Correlated Stream: {risk.get('correlated_score', 0)}")
    print(f"{'='*60}")

    # Compliance summary
    comp = result.get("compliance", {})
    if comp.get("nist_controls"):
        print(f"\n  NIST 800-53: {', '.join(comp['nist_controls'][:5])}...")
    if comp.get("iso27001_clauses"):
        print(f"  ISO 27001:  {', '.join(comp['iso27001_clauses'][:5])}...")
    if comp.get("hipaa_safeguards"):
        print(f"  HIPAA:      {', '.join(comp['hipaa_safeguards'][:5])}...")


def save_report(result, output_path):
    """Save full JSON report."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\n[Report] Saved to {output_path}")


def run_demo():
    """
    Run demo mode: scan bad config then good config,
    show before/after comparison.
    """
    bad_config = os.path.join(SAMPLE_DIR, "bad_aws_config.json")
    good_config = os.path.join(SAMPLE_DIR, "good_aws_config.json")
    trivy_file = os.path.join(SAMPLE_DIR, "sample_trivy_output.json")

    print("=" * 60)
    print("  CloudShield — DEMO MODE")
    print("=" * 60)

    # BEFORE scan
    print("\n▶ BEFORE — Scanning vulnerable configuration...")
    print("-" * 60)
    before = run_pipeline(config=bad_config, trivy_output=trivy_file)
    for line in before.get("execution_log", []):
        print(f"  {line}")

    # AFTER scan
    print("\n▶ AFTER — Scanning secure configuration...")
    print("-" * 60)
    after = run_pipeline(config=good_config)
    for line in after.get("execution_log", []):
        print(f"  {line}")

    # Comparison
    b_risk = before.get("risk", {})
    a_risk = after.get("risk", {})
    b_findings = len(before.get("findings", []))
    a_findings = len(after.get("findings", []))
    b_crit = sum(1 for f in before.get("findings", []) if f.get("severity") == "CRITICAL")
    a_crit = sum(1 for f in after.get("findings", []) if f.get("severity") == "CRITICAL")

    comparison = [
        ["Total Issues", b_findings, a_findings, f"{b_findings - a_findings} reduced"],
        ["Critical", b_crit, a_crit, f"{b_crit - a_crit} fixed"],
        ["Risk Score", b_risk.get("final_score", 0), a_risk.get("final_score", 0),
         f"{((b_risk.get('final_score',1) - a_risk.get('final_score',0)) / max(b_risk.get('final_score',1), 0.01) * 100):.0f}% reduction"],
        ["Category", b_risk.get("category", "N/A"), a_risk.get("category", "N/A"), "—"],
    ]

    print("\n" + "=" * 60)
    print("  BEFORE vs AFTER COMPARISON")
    print("=" * 60)

    if tabulate:
        print(tabulate(comparison, headers=["Metric", "BEFORE", "AFTER", "Change"], tablefmt="grid"))
    else:
        print(f"{'Metric':<18}{'BEFORE':<12}{'AFTER':<12}{'Change'}")
        print("-" * 55)
        for row in comparison:
            print(f"{row[0]:<18}{str(row[1]):<12}{str(row[2]):<12}{row[3]}")

    # Save demo comparison
    os.makedirs(REPORTS_DIR, exist_ok=True)
    demo_report = {"before": before, "after": after, "comparison": comparison}
    demo_path = os.path.join(REPORTS_DIR, "demo_comparison.json")
    with open(demo_path, "w", encoding="utf-8") as f:
        json.dump(demo_report, f, indent=2, default=str)
    print(f"\n[Demo] Comparison saved to {demo_path}")

    return demo_report


def main():
    parser = argparse.ArgumentParser(
        description="CloudShield — Unified Detection & Remediation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--image", help="Docker image to scan (e.g., nginx:1.14)")
    parser.add_argument("--config", help="Cloud config JSON file to validate")
    parser.add_argument("--trivy-output", help="Pre-generated Trivy JSON output file")
    parser.add_argument("--output", help="Output JSON report path", default=os.path.join(REPORTS_DIR, "report.json"))
    parser.add_argument("--dashboard", action="store_true", help="Launch Flask dashboard after scan")
    parser.add_argument("--demo", action="store_true", help="Run demo with before/after comparison")

    args = parser.parse_args()

    if args.demo:
        run_demo()
        if args.dashboard:
            _launch_dashboard()
        return

    if not args.image and not args.config and not args.trivy_output:
        parser.print_help()
        print("\nError: Provide at least --image, --config, or --trivy-output")
        sys.exit(1)

    print("=" * 60)
    print("  CloudShield — Unified Detection & Remediation")
    print("=" * 60)

    result = run_pipeline(image=args.image, config=args.config, trivy_output=args.trivy_output)

    # Print execution log
    for line in result.get("execution_log", []):
        print(f"  {line}")

    # Print table
    print_cli_table(result)

    # Save report
    save_report(result, args.output)

    if args.dashboard:
        _launch_dashboard()


def _launch_dashboard():
    print("\n[Dashboard] Starting Flask dashboard on http://localhost:5000")
    sys.path.insert(0, os.path.join(BASE_DIR, "dashboard"))
    from dashboard.app import create_app
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()
