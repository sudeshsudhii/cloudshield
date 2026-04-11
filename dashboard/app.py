"""
CloudShield Flask Dashboard
Lightweight visualization for demo purposes with result caching.
"""

import json
import os
import sys
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import run_pipeline, run_demo

CACHE_FILE = os.path.join(os.path.dirname(__file__), "results_cache.json")
CACHE_TTL = 300  # 5 minutes
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_data")


def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")

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
        with open(CACHE_FILE, "w") as f:
            json.dump({"cached_at": time.time(), "data": data}, f, indent=2, default=str)

    @app.route("/")
    def index():
        return render_template("index.html")

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

        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(os.path.join(REPORTS_DIR, "demo_comparison.json"), "w") as f:
            json.dump(demo_data, f, indent=2, default=str)

        _save_cache(before)
        return jsonify({"status": "completed", "data": demo_data})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
