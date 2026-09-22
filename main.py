"""
Main entry point. Wires recon -> nuclei -> zap -> summarize -> report
into a LangGraph pipeline and runs it against a URL you provide.

Usage:
    python main.py https://example.com
"""
import sys
from typing import TypedDict, Optional, List, Dict, Any

from dotenv import load_dotenv
from langgraph.graph import StateGraph, END

from nodes.recon import recon_node
from nodes.nuclei_scan import nuclei_scan_node
from nodes.zap_scan import zap_scan_node
from nodes.nikto_scan import nikto_scan_node
from nodes.wapiti_scan import wapiti_scan_node
from nodes.wpscan_scan import wpscan_node
from nodes.ffuf_scan import ffuf_scan_node
from nodes.summarize import summarize_node
from nodes.report import report_node

load_dotenv()


class ScanState(TypedDict, total=False):
    url: str
    recon: Dict[str, Any]
    nuclei_results: Dict[str, Any]
    zap_results: Dict[str, Any]
    nikto_results: Dict[str, Any]
    wapiti_results: Dict[str, Any]
    wpscan_results: Dict[str, Any]
    ffuf_results: Dict[str, Any]
    summary: str
    summary_json: Dict[str, Any]
    report_path: str


def build_graph():
    graph = StateGraph(ScanState)

    graph.add_node("recon", recon_node)
    graph.add_node("nuclei_scan", nuclei_scan_node)
    graph.add_node("zap_scan", zap_scan_node)
    graph.add_node("nikto_scan", nikto_scan_node)
    graph.add_node("wapiti_scan", wapiti_scan_node)
    graph.add_node("wpscan", wpscan_node)
    graph.add_node("ffuf_scan", ffuf_scan_node)
    graph.add_node("summarize", summarize_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "nuclei_scan")
    graph.add_edge("nuclei_scan", "zap_scan")
    graph.add_edge("zap_scan", "nikto_scan")
    graph.add_edge("nikto_scan", "wapiti_scan")
    graph.add_edge("wapiti_scan", "wpscan")       # wpscan self-skips if no WordPress detected
    graph.add_edge("wpscan", "ffuf_scan")
    graph.add_edge("ffuf_scan", "summarize")
    graph.add_edge("summarize", "report")
    graph.add_edge("report", END)

    return graph.compile()


def confirm_authorization(url: str) -> bool:
    print(f"\nTarget: {url}")
    answer = input(
        "Do you own this site or have explicit written authorization to "
        "scan it? (yes/no): "
    ).strip().lower()
    return answer == "yes"


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <url>")
        sys.exit(1)

    url = sys.argv[1]

    if not confirm_authorization(url):
        print("Aborting. Only scan sites you own or are authorized to test.")
        sys.exit(1)

    app = build_graph()
    print(f"\nRunning scan pipeline against {url} ...\n")
    final_state = app.invoke({"url": url})

    print("=" * 60)
    print(final_state.get("summary", "No summary produced."))
    print("=" * 60)


if __name__ == "__main__":
    main()
