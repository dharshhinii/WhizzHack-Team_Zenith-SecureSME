"""
Report node: writes the final Markdown report to the reports/ folder.
"""
import datetime
import os
import re


def report_node(state: dict) -> dict:
    url = state["url"]
    safe_name = re.sub(r"[^a-zA-Z0-9]+", "_", url).strip("_")[:60]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{safe_name}_{timestamp}.md"

    os.makedirs("reports", exist_ok=True)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# Security Scan Report\n\n")
        f.write(f"**Target:** {url}\n\n")
        f.write(f"**Generated:** {datetime.datetime.now().isoformat()}\n\n")
        f.write("---\n\n")
        f.write(str(state.get("summary", "No summary generated.")))
        f.write("\n\n---\n\n## Raw Data Appendix\n\n")
        f.write(f"### Recon\n```json\n{state.get('recon')}\n```\n\n")
        f.write(f"### Nuclei\n```json\n{state.get('nuclei_results')}\n```\n\n")
        f.write(f"### ZAP\n```json\n{state.get('zap_results')}\n```\n\n")
        f.write(f"### Nikto\n```json\n{state.get('nikto_results')}\n```\n\n")
        f.write(f"### Wapiti\n```json\n{state.get('wapiti_results')}\n```\n\n")
        f.write(f"### WPScan\n```json\n{state.get('wpscan_results')}\n```\n\n")
        f.write(f"### ffuf\n```json\n{state.get('ffuf_results')}\n```\n")

    state["report_path"] = filename
    print(f"\n[+] Report written to: {filename}\n")
    return state
