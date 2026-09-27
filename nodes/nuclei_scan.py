"""
Nuclei node: runs template-based vulnerability scanning and captures JSON output.
Requires nuclei to be installed: https://github.com/projectdiscovery/nuclei
"""
import json
import os
import subprocess


def nuclei_scan_node(state: dict) -> dict:
    url = state["url"]
    nuclei_path = os.getenv("NUCLEI_PATH", "nuclei")
    timeout = int(os.getenv("SCAN_TIMEOUT", "180"))

    findings = []
    error = None

    try:
        result = subprocess.run(
            [nuclei_path, "-u", url, "-jsonl", "-silent",
             "-severity", "low,medium,high,critical"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if result.returncode not in (0, 1) and not findings:
            error = f"nuclei exited {result.returncode}: {result.stderr[:500]}"

    except FileNotFoundError:
        error = "nuclei not found. Install it or set NUCLEI_PATH in .env"
    except subprocess.TimeoutExpired:
        error = f"nuclei timed out after {timeout}s"

    state["nuclei_results"] = {"findings": findings, "error": error}
    return state
