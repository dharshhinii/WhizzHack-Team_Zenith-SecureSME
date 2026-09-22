"""Wapiti node: black-box scan, JSON report output."""
import json
import os
import subprocess
import tempfile


def wapiti_scan_node(state: dict) -> dict:
    url = state["url"]
    wapiti_path = os.getenv("WAPITI_PATH", "wapiti")
    timeout = int(os.getenv("SCAN_TIMEOUT", "180"))

    findings = {}
    error = None

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "wapiti_report.json")
        try:
            result = subprocess.run(
                [wapiti_path, "-u", url, "-f", "json", "-o", report_path],
                capture_output=True, text=True, timeout=timeout,
            )
            if os.path.exists(report_path):
                with open(report_path) as f:
                    data = json.load(f)
                findings = data.get("vulnerabilities", {})
            else:
                error = f"wapiti produced no report: {result.stderr[:500]}"

        except FileNotFoundError:
            error = "wapiti not found. Install it or set WAPITI_PATH in .env"
        except subprocess.TimeoutExpired:
            error = f"wapiti timed out after {timeout}s"

    state["wapiti_results"] = {"findings": findings, "error": error}
    return state
