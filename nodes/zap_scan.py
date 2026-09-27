"""
ZAP node: runs the passive baseline scan (safe for repeated automated runs --
it does NOT actively attack the site, just crawls and inspects responses).
Requires zap-baseline.py, typically run via the official Docker image:
docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap-baseline.py \
    -t <url> -J report.json
"""
import json
import os
import subprocess
import tempfile


def zap_scan_node(state: dict) -> dict:
    url = state["url"]
    zap_path = os.getenv("ZAP_BASELINE_PATH", "zap-baseline.py")
    timeout = int(os.getenv("SCAN_TIMEOUT", "180"))

    alerts = []
    error = None

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "zap_report.json")
        try:
            result = subprocess.run(
                [zap_path, "-t", url, "-J", "zap_report.json"],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmpdir,
            )
            if os.path.exists(report_path):
                with open(report_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                alerts = data.get("site", [{}])[0].get("alerts", [])
            else:
                error = f"zap-baseline produced no report: {result.stderr[:500]}"

        except FileNotFoundError:
            error = "zap-baseline.py not found. Install ZAP or set ZAP_BASELINE_PATH in .env"
        except subprocess.TimeoutExpired:
            error = f"zap-baseline timed out after {timeout}s"

    state["zap_results"] = {"alerts": alerts, "error": error}
    return state
