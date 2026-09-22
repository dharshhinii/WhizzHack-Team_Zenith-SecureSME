"""
active_tools.py — SQLmap, Commix, and XSStrike wrappers.

These are NOT part of the automated graph in main.py on purpose. SQLi and
command-injection tools actively send exploit payloads (not just passive
detection), so each run here requires you to type a literal confirmation
phrase referencing the exact target, every time -- no flag-skipping.

Usage:
    python active_tools.py sqlmap https://target.com/page?id=1
    python active_tools.py commix https://target.com/page?cmd=ping
    python active_tools.py xsstrike https://target.com/search?q=test
"""
import subprocess
import sys
import os

TOOL_PATHS = {
    "sqlmap": os.getenv("SQLMAP_PATH", "sqlmap"),
    "commix": os.getenv("COMMIX_PATH", "commix"),
    "xsstrike": os.getenv("XSSTRIKE_PATH", "xsstrike"),
}

TOOL_ARGS = {
    "sqlmap": lambda url: [TOOL_PATHS["sqlmap"], "-u", url, "--batch", "--level=1", "--risk=1"],
    "commix": lambda url: [TOOL_PATHS["commix"], "--url", url, "--batch"],
    "xsstrike": lambda url: [TOOL_PATHS["xsstrike"], "-u", url],
}


def confirm(tool: str, url: str) -> bool:
    phrase = f"I AM AUTHORIZED TO TEST {url}"
    print(f"\n{tool} sends live exploit/injection payloads to the target.")
    print("Only proceed if you own this site or have explicit written authorization.")
    typed = input(f'Type exactly: "{phrase}"\n> ').strip()
    return typed == phrase


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in TOOL_ARGS:
        print(f"Usage: python active_tools.py <{'|'.join(TOOL_ARGS)}> <url>")
        sys.exit(1)

    tool, url = sys.argv[1], sys.argv[2]

    if not confirm(tool, url):
        print("Confirmation phrase did not match. Aborting.")
        sys.exit(1)

    cmd = TOOL_ARGS[tool](url)
    try:
        subprocess.run(cmd, timeout=int(os.getenv("SCAN_TIMEOUT", "300")))
    except FileNotFoundError:
        print(f"{tool} not found. Install it first (see INSTALL.md).")
    except subprocess.TimeoutExpired:
        print(f"{tool} timed out.")


if __name__ == "__main__":
    main()
