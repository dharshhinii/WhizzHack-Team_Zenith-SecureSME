"""Nikto node: scans for outdated software, dangerous files, misconfigs."""
import json
import os
import subprocess


def nikto_scan_node(state: dict) -> dict:
    url = state["url"]
    nikto_path = os.getenv("NIKTO_PATH", "nikto")
    timeout = int(os.getenv("SCAN_TIMEOUT", "180"))

    findings = []
    error = None

    try:
        result = subprocess.run(
            [nikto_path, "-h", url, "-Format", "json", "-output", "-"],
            capture_output=True, text=True, timeout=timeout,
        )
        try:
            data = json.loads(result.stdout)
            findings = data.get("vulnerabilities", [])
        except json.JSONDecodeError:
            # Fall back to raw text if JSON output isn't supported by this build
            findings = [{"raw": result.stdout[:3000]}]

    except FileNotFoundError:
        error = "nikto not found. Install it or set NIKTO_PATH in .env"
    except subprocess.TimeoutExpired:
        error = f"nikto timed out after {timeout}s"

    state["nikto_results"] = {"findings": findings, "error": error}
    return state
