"""
CloudShield Remediation Engine
Multi-strategy, rule-based remediation with fallback chain.
"""

PKG_COMMANDS = {
    "debian": "apt-get install --only-upgrade {pkg}={version}",
    "ubuntu": "apt-get install --only-upgrade {pkg}={version}",
    "alpine": "apk add --no-cache {pkg}={version}",
    "centos": "yum update -y {pkg}",
    "rhel": "yum update -y {pkg}",
}

POLICY_FIXES = {
    "s3_public": {
        "title": "Block S3 Public Access",
        "fix": "aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,BlockPublicPolicy=true,IgnorePublicAcls=true,RestrictPublicBuckets=true",
        "confidence": "high",
    },
    "iam_wildcard": {
        "title": "Apply Least-Privilege IAM",
        "fix": "Replace {\"Action\":\"*\",\"Resource\":\"*\"} with specific actions/resources.\naws iam put-role-policy --role-name <ROLE> --policy-name <POLICY> --policy-document file://least-privilege.json",
        "confidence": "high",
    },
    "encryption_disabled": {
        "title": "Enable S3 Encryption",
        "fix": "aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
        "confidence": "high",
    },
    "logging_disabled": {
        "title": "Enable Logging",
        "fix": "aws cloudtrail create-trail --name main-trail --s3-bucket-name <LOG_BUCKET> --is-multi-region-trail --enable-log-file-validation",
        "confidence": "high",
    },
    "mfa_not_required": {
        "title": "Enable MFA",
        "fix": "Add Condition: {\"Bool\":{\"aws:MultiFactorAuthPresent\":\"true\"}} to IAM policy",
        "confidence": "high",
    },
    "privileged_container": {
        "title": "Remove Privileged Mode",
        "fix": "Set privileged: false in docker-compose.yml. Add security_opt: [no-new-privileges:true]. Use cap_add for specific capabilities only.",
        "confidence": "high",
    },
    "root_container": {
        "title": "Run as Non-Root",
        "fix": "Add to Dockerfile: RUN addgroup -S app && adduser -S app -G app\nUSER app",
        "confidence": "high",
    },
    "read_only_rootfs": {
        "title": "Read-Only Root FS",
        "fix": "docker run --read-only --tmpfs /tmp --tmpfs /var/run <image>",
        "confidence": "high",
    },
}


def generate_remediations(findings):
    """Generate remediation actions for all findings."""
    remediations = []
    for finding in findings:
        src = finding.get("source", "")
        ftype = finding.get("type", "")
        if ftype == "CVE" and src == "trivy":
            remediations.append(_remediate_cve(finding))
        elif ftype == "POLICY" and src == "opa":
            remediations.append(_remediate_policy(finding))
        elif ftype == "CORRELATED" and src == "correlation":
            remediations.append(_remediate_correlated(finding))
        else:
            remediations.append(_remediate_generic(finding))
    return remediations


def _remediate_cve(f):
    pkg, fixed, installed = f.get("package",""), f.get("fixed_version",""), f.get("installed_version","")
    pkg_type, cve_id, target = f.get("pkg_type","debian").lower(), f.get("id",""), f.get("target","")

    if fixed:
        cmd_tpl = PKG_COMMANDS.get(pkg_type, PKG_COMMANDS["debian"])
        return {"finding_id": cve_id, "type": "CVE", "strategy": "package_upgrade",
                "confidence": "high", "title": f"Upgrade {pkg} to {fixed}",
                "command": cmd_tpl.format(pkg=pkg, version=fixed),
                "description": f"Upgrade {pkg} from {installed} to {fixed} to fix {cve_id}"}

    if target:
        base = target.split(" ")[0] if " " in target else target
        return {"finding_id": cve_id, "type": "CVE", "strategy": "base_image_update",
                "confidence": "medium", "title": f"Update base image for {pkg}",
                "command": f"# Update FROM {base} to FROM {base.split(':')[0]}:latest",
                "description": f"No fixed version for {pkg} ({cve_id}). Update base image."}

    return {"finding_id": cve_id, "type": "CVE", "strategy": "dockerfile_rebuild",
            "confidence": "low", "title": f"Rebuild with secure {pkg}",
            "command": f"RUN apt-get update && apt-get install -y {pkg} && rm -rf /var/lib/apt/lists/*",
            "description": f"Rebuild image with updated {pkg} or use distroless base."}


def _remediate_policy(f):
    msg = f.get("message", "").lower()
    fix_key = None
    if "public" in msg and "s3" in msg: fix_key = "s3_public"
    elif "wildcard" in msg or "'*'" in msg: fix_key = "iam_wildcard"
    elif "encryption" in msg: fix_key = "encryption_disabled"
    elif "logging" in msg or "cloudtrail" in msg: fix_key = "logging_disabled"
    elif "mfa" in msg: fix_key = "mfa_not_required"
    elif "privileged mode" in msg: fix_key = "privileged_container"
    elif "root user" in msg or "runs as root" in msg: fix_key = "root_container"
    elif "read-only" in msg or "read_only" in msg: fix_key = "read_only_rootfs"

    if fix_key and fix_key in POLICY_FIXES:
        t = POLICY_FIXES[fix_key]
        return {"finding_id": f.get("id",""), "type": "POLICY", "strategy": "config_fix",
                "confidence": t["confidence"], "title": t["title"],
                "command": t["fix"], "description": f"Fix: {f.get('message','')}"}

    return _remediate_generic(f)


def _remediate_correlated(f):
    rule = f.get("correlation_rule", "")
    ids = f.get("source_finding_ids", [])
    if rule == "exposed_vulnerability":
        return {"finding_id": f.get("id",""), "type": "CORRELATED", "strategy": "multi_fix",
                "confidence": "high", "title": "Fix Exposed Vulnerability (2-step)",
                "command": "1) Patch vulnerable package (see CVE fix)\n2) Block public access: aws s3api put-public-access-block ...",
                "description": f"Fix both vulnerability and exposure. Sources: {', '.join(ids)}"}
    elif rule == "privilege_escalation_risk":
        return {"finding_id": f.get("id",""), "type": "CORRELATED", "strategy": "multi_fix",
                "confidence": "high", "title": "Fix Privilege Escalation (2-step)",
                "command": "1) Set privileged:false, add USER nonroot\n2) Replace Action:* with least-privilege",
                "description": f"Fix container privileges + IAM wildcards. Sources: {', '.join(ids)}"}
    return _remediate_generic(f)


def _remediate_generic(f):
    return {"finding_id": f.get("id",""), "type": f.get("type","UNKNOWN"),
            "strategy": "manual_review", "confidence": "low",
            "title": f"Review: {f.get('title','Unknown')}",
            "command": f"# Manual review: {f.get('description','')}",
            "description": f.get("description", "Review this finding.")}


def get_remediation_summary(remediations):
    by_strategy, by_confidence = {}, {"high": 0, "medium": 0, "low": 0}
    for r in remediations:
        s = r.get("strategy", "unknown")
        by_strategy[s] = by_strategy.get(s, 0) + 1
        c = r.get("confidence", "low")
        if c in by_confidence: by_confidence[c] += 1
    return {"total": len(remediations), "by_strategy": by_strategy, "by_confidence": by_confidence}
