"""
Recon node: fingerprints the target so later nodes can decide what to run.
Uses a lightweight HTTP request + header/body inspection instead of a heavy
tool, so it works even before you've installed nuclei/zap.
"""
import requests


def recon_node(state: dict) -> dict:
    url = state["url"]
    tech_hints = []
    status_code = None
    server_header = None
    error = None

    try:
        resp = requests.get(url, timeout=15, allow_redirects=True)
        status_code = resp.status_code
        server_header = resp.headers.get("Server", "unknown")
        body = resp.text.lower()

        # Very basic fingerprinting -- expand as needed
        if "wp-content" in body or "wordpress" in body:
            tech_hints.append("wordpress")
        if "x-drupal-cache" in resp.headers:
            tech_hints.append("drupal")
        if "django" in server_header.lower():
            tech_hints.append("django")
        if "cf-ray" in resp.headers:
            tech_hints.append("cloudflare")

    except requests.RequestException as e:
        error = str(e)

    state["recon"] = {
        "status_code": status_code,
        "server_header": server_header,
        "tech_hints": tech_hints,
        "error": error,
    }
    return state
