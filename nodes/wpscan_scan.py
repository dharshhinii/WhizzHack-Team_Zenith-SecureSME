"""
WPScan node: only makes sense (and only runs) if recon detected WordPress.
Requires a free API token from https://wpscan.com/api for vuln-database lookups
(works without one too, just with less CVE detail).
"""
import json
import os
import subprocess


def wpscan_node(state: dict) -> dict:
    url = state["url"]
    tech_hints = state.get("recon", {}).get("tech_hints", [])

    if "wordpress" not in tech_hints:
        state["wpscan_results"] = {"skipped": True, "reason": "WordPress not detected"}
        return state

    wpscan_path = os.getenv("WPSCAN_PATH", "wpscan")
    api_token = os.getenv("WPSCAN_API_TOKEN", "")
    timeout = int(os.getenv("SCAN_TIMEOUT", "180"))

    findings = {}
    error = None

    cmd = [wpscan_path, "--url", url, "--format", "json", "--no-banner"]
    if api_token:
        cmd += ["--api-token", api_token]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        try:
            findings = json.loads(result.stdout)
        except json.JSONDecodeError:
            error = f"wpscan output not valid JSON: {result.stderr[:500]}"

    except FileNotFoundError:
        error = "wpscan not found. Install it or set WPSCAN_PATH in .env"
    except subprocess.TimeoutExpired:
        error = f"wpscan timed out after {timeout}s"

    state["wpscan_results"] = {"findings": findings, "error": error}
    return state
