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
import re
from botocore.exceptions import ClientError, BotoCoreError
from botocore.config import Config

# Multi-cloud SDKs
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError
from google.cloud import storage
from google.api_core.exceptions import GoogleAPIError
from google.oauth2 import service_account

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
    
    ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173,https://cloudshield-vtah.vercel.app").split(",")
    CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})
    
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

    @app.before_request
    def log_request_info():
        # Keep OPTIONS bypass clean
        if request.endpoint == 'OPTIONS':
            return

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

    # ── NEW: Real-Time System Agent Endpoints ──
    AGENT_CACHE = {}

    @app.route("/api/agent-scan", methods=["POST", "OPTIONS"])
    @limiter.exempt
    def api_agent_scan():
        if request.method == "OPTIONS":
            return jsonify({}), 200

        # Validate agent key
        required_key = os.environ.get("AGENT_KEY", "default-agent-key-123")
        provided_key = request.headers.get("x-agent-key")
        
        if provided_key != required_key:
            return jsonify({"status": "error", "message": "Unauthorized agent"}), 403

        try:
            payload = request.get_json(silent=True)
            if not payload or not isinstance(payload, dict):
                return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

            # Calculate Risk Score
            # 1. Base on OS/Load
            load = payload.get("cpu_percent", 0)
            ports = payload.get("open_ports", [])
            cves = payload.get("cves", {"critical": 0, "high": 0, "medium": 0, "low": 0})
            
            risk_score = 0
            if load > 90: risk_score += 10
            elif load > 75: risk_score += 5
            
            risk_score += len(ports) * 2 # 2 points per open port
            risk_score += cves.get("critical", 0) * 20
            risk_score += cves.get("high", 0) * 10
            risk_score += cves.get("medium", 0) * 5
            
            if risk_score > 100: risk_score = 100
            
            if risk_score >= 80: risk_level = "Critical"
            elif risk_score >= 60: risk_level = "High"
            elif risk_score >= 40: risk_level = "Medium"
            else: risk_level = "Low"

            payload["risk_score"] = risk_score
            payload["risk_level"] = risk_level

            # Store in global cache with timestamp
            agent_id = payload.get("agentId", "unknown")
            AGENT_CACHE[agent_id] = {
                "timestamp": time.time(),
                "data": payload
            }
            
            return jsonify({"status": "success", "message": "Telemetry received"})
        except Exception as e:
            return jsonify({"status": "error", "message": "Server processing error"}), 500

    @app.route("/api/agent-status", methods=["GET"])
    def api_agent_status():
        agent_id = request.args.get("agentId", "unknown")
        
        # If no explicit ID is requested, return the most recent active one (for single-agent demo)
        if agent_id == "unknown" and AGENT_CACHE:
            # Sort by timestamp and get newest
            sorted_agents = sorted(AGENT_CACHE.values(), key=lambda x: x["timestamp"], reverse=True)
            if sorted_agents:
                entry = sorted_agents[0]
            else:
                return jsonify({"status": "offline", "message": "No active agents"}), 200
        else:
            entry = AGENT_CACHE.get(agent_id)

        if not entry:
            return jsonify({"status": "offline", "message": "Agent not found"}), 404

        time_diff = time.time() - entry["timestamp"]
        
        if time_diff <= 60:
            status = "online"
        elif time_diff <= 180:
            status = "stale"
        else:
            status = "offline"

        return jsonify({
            "status": status,
            "last_seen_seconds_ago": round(time_diff, 1),
            "data": entry["data"]
        })

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

    # ── NEW: Enterprise Storage Check Endpoint ──
    STORAGE_CACHE = {}

    @app.route("/api/check-storage", methods=["POST", "OPTIONS"])
    @limiter.limit("10 per minute")
    @limiter.limit("100 per day")
    def api_check_storage():
        start_time = time.perf_counter()
        scanned_at = datetime.utcnow().isoformat() + "Z"
        
        if request.method == "OPTIONS":
            return jsonify({}), 200

        try:
            body = request.get_json(silent=True)
            if body is None:
                return jsonify({"status": "error", "message": "Failed to parse JSON configuration"}), 400

            provider = body.get("provider", "aws").lower()
            resource_name = body.get("resource", "")
            
            # Input validation
            if not isinstance(resource_name, str) or not re.match(r"^[a-zA-Z0-9.\-_]{3,255}$", resource_name):
                return jsonify({"status": "error", "message": "Invalid resource name format"}), 400

            # Caching check
            cache_key = f"{provider}:{resource_name}"
            if cache_key in STORAGE_CACHE:
                cached_entry = STORAGE_CACHE[cache_key]
                if time.time() - cached_entry['ts'] < 300: # 5 mins TTL
                    # Update dynamic time fields for cached entry
                    c_data = cached_entry['data'].copy()
                    c_data['scanDurationMs'] = round((time.perf_counter() - start_time) * 1000, 2)
                    c_data['scannedAt'] = scanned_at
                    return jsonify(c_data)

            is_public = False
            risk = "Low"
            exposure_type = "None"
            details = "Resource is securely configured and private."
            remediation = "No action required."
            confidence = 100

            boto_config = Config(connect_timeout=3, read_timeout=3, retries={'max_attempts': 1})

            if provider == "aws":
                s3_client = boto3.client('s3', config=boto_config)
                
                blocks_public_acls = False
                public_acl_found = False
                public_policy_found = False
                
                # Check Public Access Block
                try:
                    pab = s3_client.get_public_access_block(Bucket=resource_name)
                    config = pab.get('PublicAccessBlockConfiguration', {})
                    blocks_public_acls = config.get('BlockPublicAcls', False) and config.get('IgnorePublicAcls', False)
                except ClientError as e:
                    code = e.response['Error']['Code']
                    if code == 'NoSuchPublicAccessBlockConfiguration':
                        pass
                    elif code == 'AccessDenied':
                        return jsonify({"status": "error", "message": "Access Denied. Check AWS credentials."}), 403
                    elif code == 'NoSuchBucket':
                        return jsonify({"status": "error", "message": f"Bucket not found."}), 404
                    else:
                        return jsonify({"status": "error", "message": "Cloud Provider Error"}), 500
                except BotoCoreError:
                    return jsonify({"status": "error", "message": "Configuration Error"}), 500

                # Check ACL
                try:
                    acl = s3_client.get_bucket_acl(Bucket=resource_name)
                    for grant in acl.get('Grants', []):
                        uri = grant.get('Grantee', {}).get('URI', '')
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            public_acl_found = True
                            break
                except ClientError:
                    pass

                # Check Policy
                try:
                    policy_str = s3_client.get_bucket_policy(Bucket=resource_name).get('Policy', '{}')
                    policy = json.loads(policy_str)
                    for statement in policy.get('Statement', []):
                        if statement.get('Effect') == 'Allow' and statement.get('Principal') in ['*', {'AWS': '*'}]:
                            public_policy_found = True
                            if statement.get('Condition'):
                                risk = "Medium"
                                exposure_type = "restricted_public"
                                details = "Bucket Policy allows public access but enforces restrictions via conditions (e.g., IP Allowlist/VPC endpoints)."
                                confidence = 85
                            else:
                                risk = "Critical"
                                exposure_type = "Public Bucket Policy"
                                details = "Bucket Policy contains a wildcard Principal (*) with an Allow effect."
                                confidence = 95
                            break
                except ClientError:
                    pass

                if public_acl_found and not blocks_public_acls:
                    is_public = True
                    risk = "Critical"
                    exposure_type = "Public ACL"
                    details = "Bucket ACL explicitly grants access to AllUsers or AuthenticatedUsers."
                    remediation = f"aws s3api put-bucket-acl --bucket {resource_name} --acl private"
                elif public_policy_found:
                    is_public = True
                    # risk, exposure_type, details set above
                    remediation = f"aws s3api delete-bucket-policy --bucket {resource_name}"

            elif provider == "azure":
                azure_conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                if not azure_conn_str:
                    return jsonify({"status": "error", "message": "Credentials missing"}), 400
                
                try:
                    blob_service_client = BlobServiceClient.from_connection_string(azure_conn_str)
                    container_client = blob_service_client.get_container_client(resource_name)
                    props = container_client.get_container_properties()
                    if props.public_access in ['blob', 'container']:
                        is_public = True
                        risk = "Critical"
                        exposure_type = f"Public {props.public_access.capitalize()} Access"
                        details = f"Container allows unauthenticated {props.public_access} access."
                        remediation = f"az storage container set-permission --name {resource_name} --public-access off"
                except AzureError as e:
                    if 'ContainerNotFound' in str(e):
                        return jsonify({"status": "error", "message": "Container not found."}), 404
                    return jsonify({"status": "error", "message": "Azure Auth/Connection Error"}), 500

            elif provider == "gcp":
                gcp_creds_json = os.environ.get("GCP_CREDENTIALS_JSON")
                try:
                    if gcp_creds_json:
                        creds_dict = json.loads(gcp_creds_json)
                        credentials = service_account.Credentials.from_service_account_info(creds_dict)
                        gcp_client = storage.Client(credentials=credentials)
                    else:
                        return jsonify({"status": "error", "message": "Credentials missing"}), 400

                    bucket = gcp_client.bucket(resource_name)
                    if not bucket.exists():
                        return jsonify({"status": "error", "message": "Bucket not found."}), 404
                        
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        if binding.get('role') in ['roles/storage.objectViewer', 'roles/storage.legacyObjectReader', 'roles/storage.admin']:
                            if 'allUsers' in binding.get('members', []) or 'allAuthenticatedUsers' in binding.get('members', []):
                                is_public = True
                                risk = "Critical"
                                exposure_type = "Public IAM Binding"
                                details = f"IAM policy grants {binding.get('role')} to allUsers."
                                remediation = f"gcloud storage buckets remove-iam-policy-binding gs://{resource_name} --member=allUsers --role={binding.get('role')}"
                                break
                except GoogleAPIError:
                    return jsonify({"status": "error", "message": "GCP Auth/Connection Error"}), 500
                except json.JSONDecodeError:
                    return jsonify({"status": "error", "message": "Credential Parse Error."}), 500

            else:
                return jsonify({"status": "error", "message": "Unsupported provider"}), 400

            response_data = {
                "provider": provider,
                "resource": resource_name,
                "isPublic": is_public,
                "status": "FAIL" if is_public else "PASS",
                "risk": risk,
                "exposureType": exposure_type,
                "details": details,
                "remediation": remediation,
                "confidence": confidence,
                "scannedAt": scanned_at,
                "scanDurationMs": round((time.perf_counter() - start_time) * 1000, 2)
            }

            # Cache the result
            STORAGE_CACHE[cache_key] = {'ts': time.time(), 'data': response_data}

            return jsonify(response_data)
            
        except Exception:
            return jsonify({"status": "error", "message": "Internal Server Error"}), 500

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
