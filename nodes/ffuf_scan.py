"""
ffuf node: discovers hidden directories/files/parameters.
Needs a wordlist -- defaults to a small built-in list if none is configured,
but for real use point FFUF_WORDLIST at something like SecLists' common.txt.
"""
import json
import os
import subprocess
import tempfile

DEFAULT_WORDS = [
    "admin", "login", "backup", "config", "test", ".env", ".git",
    "api", "uploads", "dashboard", "wp-admin", "phpinfo.php",
]


def ffuf_scan_node(state: dict) -> dict:
    url = state["url"].rstrip("/")
    ffuf_path = os.getenv("FFUF_PATH", "ffuf")
    wordlist = os.getenv("FFUF_WORDLIST")
    timeout = int(os.getenv("SCAN_TIMEOUT", "180"))

    findings = []
    error = None

    with tempfile.TemporaryDirectory() as tmpdir:
        if not wordlist:
            wordlist = os.path.join(tmpdir, "words.txt")
            with open(wordlist, "w", encoding="utf-8") as f:
                f.write("\n".join(DEFAULT_WORDS))

        out_path = os.path.join(tmpdir, "ffuf_out.json")
        try:
            result = subprocess.run(
                [ffuf_path, "-u", f"{url}/FUZZ", "-w", wordlist,
                 "-o", out_path, "-of", "json", "-mc", "200,301,302,403"],
                capture_output=True, text=True, timeout=timeout,
            )
            if os.path.exists(out_path):
                with open(out_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                findings = data.get("results", [])
            else:
                error = f"ffuf produced no output: {result.stderr[:500]}"

        except FileNotFoundError:
            error = "ffuf not found. Install it or set FFUF_PATH in .env"
        except subprocess.TimeoutExpired:
            error = f"ffuf timed out after {timeout}s"

    state["ffuf_results"] = {"findings": findings, "error": error}
    return state
