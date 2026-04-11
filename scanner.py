"""
CloudShield Scanner Module
Wraps Trivy CLI for container image vulnerability scanning.
Falls back to file-based input when Trivy is not installed.
"""

import json
import subprocess
import shutil
import os
import sys
import platform


def check_trivy_installed():
    """Check if Trivy CLI is available on PATH."""
    return shutil.which("trivy") is not None


def get_install_instructions():
    """Return OS-specific Trivy install instructions."""
    system = platform.system().lower()
    instructions = [
        "=" * 60,
        "  TRIVY NOT FOUND",
        "=" * 60,
        "",
    ]
    if system == "windows":
        instructions.append("  Install via Chocolatey:")
        instructions.append("    choco install trivy")
        instructions.append("")
        instructions.append("  Or via Scoop:")
        instructions.append("    scoop install trivy")
    elif system == "darwin":
        instructions.append("  Install via Homebrew:")
        instructions.append("    brew install trivy")
    else:
        instructions.append("  Install via apt:")
        instructions.append("    sudo apt-get install -y trivy")
        instructions.append("")
        instructions.append("  Or via snap:")
        instructions.append("    sudo snap install trivy")

    instructions.extend([
        "",
        "  To generate scan output manually:",
        "    trivy image --format json --output trivy_output.json <image>",
        "",
        "  Then run CloudShield with:",
        "    python main.py --trivy-output trivy_output.json --config <config>",
        "=" * 60,
    ])
    return "\n".join(instructions)


def scan_image(image_name):
    """
    Scan a Docker image using Trivy CLI.
    Returns a list of vulnerability findings.
    """
    if not check_trivy_installed():
        print(get_install_instructions(), file=sys.stderr)
        return None

    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", "--quiet", image_name],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            print(f"[Scanner] Trivy scan failed: {result.stderr}", file=sys.stderr)
            return None

        trivy_data = json.loads(result.stdout)
        return parse_trivy_output(trivy_data)

    except subprocess.TimeoutExpired:
        print("[Scanner] Trivy scan timed out after 300s", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"[Scanner] Failed to parse Trivy JSON output: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[Scanner] Unexpected error: {e}", file=sys.stderr)
        return None


def scan_from_file(filepath):
    """
    Parse a pre-generated Trivy JSON output file.
    No data fabrication — reads real Trivy output.
    """
    if not os.path.exists(filepath):
        print(f"[Scanner] File not found: {filepath}", file=sys.stderr)
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            trivy_data = json.load(f)
        return parse_trivy_output(trivy_data)
    except json.JSONDecodeError as e:
        print(f"[Scanner] Invalid JSON in {filepath}: {e}", file=sys.stderr)
        return None


def parse_trivy_output(trivy_data):
    """
    Extract vulnerability findings from Trivy JSON output.
    Returns a list of normalized finding dicts.
    """
    findings = []

    results = trivy_data.get("Results", [])
    for result in results:
        target = result.get("Target", "unknown")
        pkg_type = result.get("Type", "unknown")
        vulns = result.get("Vulnerabilities", [])

        if vulns is None:
            continue

        for vuln in vulns:
            finding = {
                "id": vuln.get("VulnerabilityID", "UNKNOWN"),
                "source": "trivy",
                "type": "CVE",
                "severity": vuln.get("Severity", "UNKNOWN").upper(),
                "package": vuln.get("PkgName", "unknown"),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", ""),
                "target": target,
                "pkg_type": pkg_type,
                "references": vuln.get("References", []),
            }
            findings.append(finding)

    return findings


def get_scan_summary(findings):
    """Return a summary dict of scan results."""
    if findings is None:
        return {"status": "error", "message": "Scan failed or Trivy not available"}

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "status": "completed",
        "total_vulnerabilities": len(findings),
        "severity_distribution": severity_counts,
    }
