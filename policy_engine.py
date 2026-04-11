"""
CloudShield Policy Engine
Wraps OPA CLI for Rego policy evaluation.
Falls back to built-in Python evaluation when OPA is not installed.
"""

import json
import subprocess
import shutil
import os
import sys
import platform


def check_opa_installed():
    """Check if OPA CLI is available on PATH."""
    return shutil.which("opa") is not None


def get_install_instructions():
    """Return OS-specific OPA install instructions."""
    system = platform.system().lower()
    instructions = [
        "=" * 60,
        "  OPA NOT FOUND — Using built-in Python policy evaluator",
        "=" * 60,
        "",
    ]
    if system == "windows":
        instructions.append("  Install via Chocolatey:")
        instructions.append("    choco install opa")
        instructions.append("")
        instructions.append("  Or download from:")
        instructions.append("    https://www.openpolicyagent.org/docs/latest/#running-opa")
    elif system == "darwin":
        instructions.append("  Install via Homebrew:")
        instructions.append("    brew install opa")
    else:
        instructions.append("  Install via apt/snap or download binary:")
        instructions.append("    curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64")
        instructions.append("    chmod +x opa && sudo mv opa /usr/local/bin/")

    instructions.extend([
        "",
        "  Falling back to built-in Python policy evaluation.",
        "  Results are equivalent — same rules, same logic.",
        "=" * 60,
    ])
    return "\n".join(instructions)


# ──────────────────────────────────────────────────────────
# OPA CLI Evaluation
# ──────────────────────────────────────────────────────────

def evaluate_with_opa(config_path, policies_dir):
    """Evaluate policies using OPA CLI."""
    findings = []
    policy_packages = [
        ("cloudshield.s3_public", "s3_public.rego", "HIGH"),
        ("cloudshield.iam_wildcard", "iam_wildcard.rego", "CRITICAL"),
        ("cloudshield.cis_basic", "cis_basic.rego", "MEDIUM"),
    ]

    for pkg, rego_file, default_severity in policy_packages:
        rego_path = os.path.join(policies_dir, rego_file)
        if not os.path.exists(rego_path):
            continue

        try:
            result = subprocess.run(
                [
                    "opa", "eval",
                    "-i", config_path,
                    "-d", rego_path,
                    "--format", "json",
                    f"data.{pkg}.violations",
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"[Policy] OPA eval failed for {rego_file}: {result.stderr}", file=sys.stderr)
                continue

            opa_output = json.loads(result.stdout)
            violations = _extract_opa_violations(opa_output)

            for violation_msg in violations:
                severity = _derive_severity(violation_msg, default_severity)
                findings.append({
                    "id": f"POLICY-{rego_file.replace('.rego', '').upper()}-{len(findings)+1}",
                    "source": "opa",
                    "type": "POLICY",
                    "severity": severity,
                    "policy": pkg,
                    "rule_file": rego_file,
                    "message": violation_msg,
                    "title": f"Policy Violation: {rego_file.replace('.rego', '').replace('_', ' ').title()}",
                    "description": violation_msg,
                })

        except Exception as e:
            print(f"[Policy] Error evaluating {rego_file}: {e}", file=sys.stderr)

    return findings


def _extract_opa_violations(opa_output):
    """Extract violation messages from OPA JSON output."""
    violations = []
    try:
        result = opa_output.get("result", [])
        if result:
            expressions = result[0].get("expressions", [])
            for expr in expressions:
                value = expr.get("value", [])
                if isinstance(value, list):
                    violations.extend(value)
                elif isinstance(value, set):
                    violations.extend(list(value))
    except (IndexError, KeyError, TypeError):
        pass
    return violations


def _derive_severity(message, default):
    """Derive severity from violation message keywords."""
    msg_lower = message.lower()
    if "wildcard" in msg_lower or "privileged" in msg_lower or "'*'" in msg_lower:
        return "CRITICAL"
    if "public" in msg_lower or "encryption" in msg_lower:
        return "HIGH"
    if "logging" in msg_lower or "mfa" in msg_lower:
        return "MEDIUM"
    return default


# ──────────────────────────────────────────────────────────
# Python Fallback Evaluator (same rules as Rego policies)
# ──────────────────────────────────────────────────────────

def evaluate_with_python(config_data):
    """
    Evaluate cloud config using built-in Python rules.
    Mirrors the same checks as the Rego policies.
    No data fabrication — same deterministic rules.
    """
    findings = []
    finding_id = 0

    # ── S3 Public Access Checks ──
    for bucket in config_data.get("s3_buckets", []):
        name = bucket.get("name", "unknown")

        acl = bucket.get("acl", "private")
        if acl in ("public-read", "public-read-write"):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.s3_public",
                "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}' has {acl} ACL",
                "title": "S3 Public Access",
                "description": f"S3 bucket '{name}' has {acl} ACL allowing public access",
            })

        pab = bucket.get("public_access_block", {})
        if not pab.get("block_public_acls", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.s3_public",
                "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}': BlockPublicAcls is not enabled",
                "title": "S3 Public Access Block",
                "description": f"S3 bucket '{name}' does not block public ACLs",
            })

        if not pab.get("block_public_policy", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-S3-PUBLIC-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.s3_public",
                "rule_file": "s3_public.rego",
                "message": f"S3 bucket '{name}': BlockPublicPolicy is not enabled",
                "title": "S3 Public Policy Block",
                "description": f"S3 bucket '{name}' does not block public policies",
            })

        # ── CIS: S3 Encryption ──
        enc = bucket.get("encryption", {})
        if not enc.get("enabled", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-ENCRYPTION-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "HIGH",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": f"S3 bucket '{name}': encryption at rest is not enabled (CIS 2.1.1)",
                "title": "Encryption Not Enabled",
                "description": f"S3 bucket '{name}' does not have encryption at rest",
            })

        # ── CIS: S3 Logging ──
        log = bucket.get("logging", {})
        if not log.get("enabled", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-LOGGING-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "MEDIUM",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": f"S3 bucket '{name}': access logging is not enabled (CIS 2.1.2)",
                "title": "Logging Not Enabled",
                "description": f"S3 bucket '{name}' does not have access logging",
            })

    # ── IAM Wildcard Checks ──
    for role in config_data.get("iam_roles", []):
        role_name = role.get("name", "unknown")
        for policy in role.get("policies", []):
            policy_name = policy.get("name", "unknown")
            action = policy.get("action", "")
            resource = policy.get("resource", "")

            if action == "*":
                finding_id += 1
                findings.append({
                    "id": f"POLICY-IAM-WILDCARD-{finding_id}",
                    "source": "opa",
                    "type": "POLICY",
                    "severity": "CRITICAL",
                    "policy": "cloudshield.iam_wildcard",
                    "rule_file": "iam_wildcard.rego",
                    "message": f"IAM role '{role_name}' policy '{policy_name}' grants wildcard Action '*'",
                    "title": "IAM Wildcard Action",
                    "description": f"IAM policy grants unrestricted actions",
                })

            if resource == "*":
                finding_id += 1
                findings.append({
                    "id": f"POLICY-IAM-WILDCARD-{finding_id}",
                    "source": "opa",
                    "type": "POLICY",
                    "severity": "CRITICAL",
                    "policy": "cloudshield.iam_wildcard",
                    "rule_file": "iam_wildcard.rego",
                    "message": f"IAM role '{role_name}' policy '{policy_name}' grants access to all Resources '*'",
                    "title": "IAM Wildcard Resource",
                    "description": f"IAM policy grants access to all resources",
                })

            if action != "*" and action.endswith(":*"):
                finding_id += 1
                findings.append({
                    "id": f"POLICY-IAM-WILDCARD-{finding_id}",
                    "source": "opa",
                    "type": "POLICY",
                    "severity": "CRITICAL",
                    "policy": "cloudshield.iam_wildcard",
                    "rule_file": "iam_wildcard.rego",
                    "message": f"IAM role '{role_name}' policy '{policy_name}' grants wildcard service action '{action}'",
                    "title": "IAM Service Wildcard",
                    "description": f"IAM policy grants all actions for a service",
                })

        # ── CIS: MFA Check ──
        if not role.get("mfa_required", True):
            finding_id += 1
            findings.append({
                "id": f"POLICY-CIS-MFA-{finding_id}",
                "source": "opa",
                "type": "POLICY",
                "severity": "MEDIUM",
                "policy": "cloudshield.cis_basic",
                "rule_file": "cis_basic.rego",
                "message": f"IAM role '{role_name}': MFA is not required (CIS 1.14)",
                "title": "MFA Not Required",
                "description": f"IAM role does not require multi-factor authentication",
            })

    # ── CloudTrail Checks ──
    ct = config_data.get("cloudtrail", {})
    if not ct.get("enabled", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CLOUDTRAIL-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "HIGH",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "CloudTrail is not enabled (CIS 3.1)",
            "title": "CloudTrail Disabled",
            "description": "AWS CloudTrail logging is not enabled",
        })

    if ct.get("enabled", False) and not ct.get("multi_region", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CLOUDTRAIL-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "MEDIUM",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "CloudTrail multi-region logging is not enabled (CIS 3.2)",
            "title": "CloudTrail Single Region",
            "description": "CloudTrail is not configured for multi-region logging",
        })

    if ct.get("enabled", False) and not ct.get("log_file_validation", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CLOUDTRAIL-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "MEDIUM",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "CloudTrail log file validation is not enabled (CIS 3.3)",
            "title": "CloudTrail No Validation",
            "description": "CloudTrail log file integrity validation is not enabled",
        })

    # ── Container Config Checks ──
    cc = config_data.get("container_config", {})
    if cc.get("privileged", False):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CONTAINER-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "CRITICAL",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "Container runs in privileged mode (CIS Docker 5.4)",
            "title": "Privileged Container",
            "description": "Container is running with full host privileges",
        })

    if cc.get("run_as_root", False):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CONTAINER-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "HIGH",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "Container runs as root user (CIS Docker 5.7)",
            "title": "Root Container",
            "description": "Container process runs as the root user",
        })

    if not cc.get("read_only_rootfs", True):
        finding_id += 1
        findings.append({
            "id": f"POLICY-CIS-CONTAINER-{finding_id}",
            "source": "opa",
            "type": "POLICY",
            "severity": "MEDIUM",
            "policy": "cloudshield.cis_basic",
            "rule_file": "cis_basic.rego",
            "message": "Container root filesystem is not read-only (CIS Docker 5.12)",
            "title": "Writable Root Filesystem",
            "description": "Container root filesystem allows writes",
        })

    return findings


def evaluate_config(config_path, policies_dir=None):
    """
    Evaluate cloud configuration against security policies.
    Uses OPA CLI if available, falls back to Python evaluation.
    """
    # Load config data
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config_data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[Policy] Failed to load config: {e}", file=sys.stderr)
        return []

    # Try OPA CLI first
    if check_opa_installed() and policies_dir:
        print("[Policy] Using OPA CLI for policy evaluation")
        findings = evaluate_with_opa(config_path, policies_dir)
        if findings is not None:
            return findings
        print("[Policy] OPA CLI evaluation failed, falling back to Python", file=sys.stderr)

    # Fallback to Python evaluator
    if not check_opa_installed():
        print(get_install_instructions(), file=sys.stderr)
    print("[Policy] Using built-in Python policy evaluator")
    return evaluate_with_python(config_data)


def get_policy_summary(findings):
    """Return a summary dict of policy evaluation results."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "status": "completed",
        "total_violations": len(findings),
        "severity_distribution": severity_counts,
    }
