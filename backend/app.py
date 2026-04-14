"""
CloudShield Flask API v2.0
Backend API with CORS, rate limiting, and raw config scanning.
"""

import json
import os
import sys
import time
import tempfile
import yaml
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from main import run_pipeline, run_demo
from policy_engine import evaluate_with_python
from correlation import correlate
from risk_engine import compute_risk_scores
from remediation import generate_remediations
from compliance import map_compliance, get_compliance_summary
from scanner import parse_trivy_output, get_scan_summary

CACHE_FILE = os.path.join(os.path.dirname(__file__), "results_cache.json")
CACHE_TTL = 300  # 5 minutes
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_data")


def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

    def _load_cache():
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r") as f:
                    cache = json.load(f)
                ts = cache.get("cached_at", 0)
                if time.time() - ts < CACHE_TTL:
                    return cache.get("data")
            except (json.JSONDecodeError, KeyError):
                pass
        return None

    def _save_cache(data):
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump({"cached_at": time.time(), "data": data}, f, indent=2, default=str)
        except Exception:
            pass  # Render's ephemeral FS may block writes

    # ── Health Check ──
    @app.route("/")
    def health():
        return jsonify({"status": "ok", "service": "cloudshield-api", "timestamp": datetime.now().isoformat()})

    @app.route("/api/results")
    def api_results():
        cached = _load_cache()
        if cached:
            return jsonify({"status": "cached", "data": cached})
        return jsonify({"status": "no_data", "data": None})

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        body = request.get_json(silent=True) or {}
        image = body.get("image")
        config = body.get("config")
        trivy_output = body.get("trivy_output")

        if not config and not image and not trivy_output:
            config = os.path.join(SAMPLE_DIR, "bad_aws_config.json")
            trivy_output = os.path.join(SAMPLE_DIR, "sample_trivy_output.json")

        result = run_pipeline(image=image, config=config, trivy_output=trivy_output)
        _save_cache(result)
        return jsonify({"status": "completed", "data": result})

    @app.route("/api/demo", methods=["POST"])
    def api_demo():
        bad_config = os.path.join(SAMPLE_DIR, "bad_aws_config.json")
        good_config = os.path.join(SAMPLE_DIR, "good_aws_config.json")
        trivy_file = os.path.join(SAMPLE_DIR, "sample_trivy_output.json")

        before = run_pipeline(config=bad_config, trivy_output=trivy_file)
        after = run_pipeline(config=good_config)

        demo_data = {
            "before": before,
            "after": after,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            os.makedirs(REPORTS_DIR, exist_ok=True)
            with open(os.path.join(REPORTS_DIR, "demo_comparison.json"), "w") as f:
                json.dump(demo_data, f, indent=2, default=str)
        except Exception:
            pass

        _save_cache(before)
        return jsonify({"status": "completed", "data": demo_data})

    # ── NEW: S3 Bucket Check Endpoint ──
    @app.route("/api/check-bucket", methods=["POST"])
    def api_check_bucket():
        try:
            # Safely parse req.body and handle errors
            body = request.get_json(silent=True)
            if body is None:
                return jsonify({"status": "error", "message": "Failed to parse JSON configuration"}), 400

            bucket_name = body.get("bucket", "")
            if not isinstance(bucket_name, str) or not bucket_name.strip():
                return jsonify({"status": "error", "message": "Bucket name is required and must be a string"}), 400

            bucket_name = bucket_name.strip()
            print(f"[AWS] Checking S3 bucket: {bucket_name}")

            # Configure boto3 using environment variables automatically
            s3_client = boto3.client('s3')
            
            # 1. get_public_access_block
            blocks_public_acls = False
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pab.get('PublicAccessBlockConfiguration', {})
                blocks_public_acls = config.get('BlockPublicAcls', False) and config.get('IgnorePublicAcls', False)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchPublicAccessBlockConfiguration':
                    blocks_public_acls = False
                elif error_code == 'AccessDenied':
                    print(f"[AWS Error] Access Denied checking PublicAccessBlock for {bucket_name}")
                    return jsonify({"status": "error", "message": "Access Denied. Check AWS credentials."}), 403
                elif error_code == 'NoSuchBucket':
                    print(f"[AWS Error] Bucket {bucket_name} not found")
                    return jsonify({"status": "error", "message": f"Bucket '{bucket_name}' not found."}), 404
                else:
                    print(f"[AWS Error] {str(e)}")
                    return jsonify({"status": "error", "message": f"AWS Error: {str(e)}"}), 500
            except BotoCoreError as e:
                print(f"[AWS Error] BotoCoreError: {str(e)}")
                return jsonify({"status": "error", "message": f"AWS Configuration error: {str(e)}"}), 500

            # 2. get_bucket_acl
            has_public_acl = False
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') in [
                        'http://acs.amazonaws.com/groups/global/AllUsers',
                        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                    ]:
                        has_public_acl = True
                        break
            except ClientError as e:
                print(f"[AWS Error] Error fetching ACLs for {bucket_name}: {str(e)}")
                pass

            # Detect public access: AllUsers ACL + no block
            is_public = has_public_acl and not blocks_public_acls

            return jsonify({
                "bucket": bucket_name,
                "isPublic": is_public,
                "status": "FAIL" if is_public else "PASS"
            })
            
        except Exception as e:
            print(f"[System Error] {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    # ── NEW: Raw Config Scan Endpoint ──
    @app.route("/api/scan-config", methods=["POST"])
    def api_scan_config():
        """
        Accept raw cloud configuration code (JSON or YAML),
        analyze for misconfigurations, compliance issues, and generate alerts + remediation.
        """
        body = request.get_json(silent=True) or {}
        raw_config = body.get("config_text", "")
        config_type = body.get("config_type", "json")  # json or yaml

        if not raw_config or not raw_config.strip():
            return jsonify({"status": "error", "message": "No configuration text provided"}), 400

        # Parse the raw config text
        try:
            if config_type == "yaml":
                config_data = yaml.safe_load(raw_config)
            else:
                config_data = json.loads(raw_config)
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            return jsonify({
                "status": "error",
                "message": f"Failed to parse {config_type.upper()} configuration: {str(e)}",
                "alerts": [{
                    "severity": "HIGH",
                    "type": "PARSE_ERROR",
                    "title": f"Invalid {config_type.upper()} Syntax",
                    "message": str(e),
                    "remediation": f"Fix the {config_type.upper()} syntax error at the specified location."
                }]
            }), 400

        if not isinstance(config_data, dict):
            return jsonify({"status": "error", "message": "Configuration must be a JSON/YAML object (not array or scalar)"}), 400

        log = []
        ts = lambda: datetime.now().strftime("%H:%M:%S")

        log.append(f"[{ts()}] Received raw {config_type.upper()} configuration ({len(raw_config)} chars)")

        # Step 1: Policy evaluation using Python engine
        log.append(f"[{ts()}] Policy Engine — evaluating raw config...")
        policy_findings = evaluate_with_python(config_data)
        pol_crit = sum(1 for f in policy_findings if f.get("severity") == "CRITICAL")
        log.append(f"[{ts()}] ✓ Policy Engine — {len(policy_findings)} violations ({pol_crit} CRITICAL)")

        # Step 2: Correlate findings
        log.append(f"[{ts()}] Correlation Engine — analyzing...")
        all_findings = correlate([], policy_findings)
        corr_count = sum(1 for f in all_findings if f.get("source") == "correlation")
        log.append(f"[{ts()}] ✓ Correlation — {corr_count} cross-source findings")

        # Step 3: Risk scoring
        risk = compute_risk_scores(all_findings)
        log.append(f"[{ts()}] ✓ Risk Scoring — Score: {risk['final_score']} ({risk['category']})")

        # Step 4: Remediation
        remediations = generate_remediations(all_findings)
        log.append(f"[{ts()}] ✓ Remediation — {len(remediations)} fix actions generated")

        # Step 5: Compliance mapping
        enriched = map_compliance(all_findings)
        comp_summary = get_compliance_summary(enriched)
        log.append(f"[{ts()}] ✓ Compliance — Mapped to {comp_summary['frameworks_impacted']} frameworks")

        # Generate alerts
        alerts = []
        for f in enriched:
            sev = f.get("severity", "LOW")
            alert = {
                "severity": sev,
                "type": f.get("type", "UNKNOWN"),
                "title": f.get("title", "Unknown Issue"),
                "message": f.get("message", f.get("description", "")),
                "id": f.get("id", ""),
                "policy": f.get("policy", ""),
            }
            if sev in ("CRITICAL", "HIGH"):
                alert["alert_level"] = "🚨 CRITICAL ALERT" if sev == "CRITICAL" else "⚠️ HIGH ALERT"
            else:
                alert["alert_level"] = "ℹ️ INFO"
            alerts.append(alert)

        result = {
            "timestamp": datetime.now().isoformat(),
            "config_type": config_type,
            "config_size": len(raw_config),
            "findings": enriched,
            "risk": risk,
            "remediations": remediations,
            "compliance": comp_summary,
            "alerts": alerts,
            "alert_summary": {
                "total": len(alerts),
                "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
                "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
                "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
                "low": sum(1 for a in alerts if a["severity"] == "LOW"),
            },
            "execution_log": log,
        }

        _save_cache(result)
        return jsonify({"status": "completed", "data": result})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
