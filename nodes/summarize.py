"""
Summarize node: three modes, tried in this order --
1. ANTHROPIC_API_KEY set -> Claude (paid per-token, best quality)
2. GEMINI_API_KEY set -> Google Gemini (genuinely free tier, no card, no expiry)
3. Neither set -> local rule-based summary (zero dependencies, zero cost)
"""
import json
import os

SYSTEM_PROMPT = """You are a cybersecurity assistant for non-technical small business owners (e.g. restaurant owners, local shop owners, freelancers).
You will be given raw output from automated scanning tools run against an authorized target URL.

You MUST respond strictly with a valid JSON object matching this schema:
{
  "safety_rating": "SAFE" | "NEEDS_ATTENTION" | "CRITICAL",
  "business_impact_score": number between 0 (very unsafe) and 100 (perfectly safe),
  "voice_summary": "A friendly 2-3 sentence audio transcript in plain English summarizing site safety, key concerns, and next steps.",
  "executive_summary": "Plain English summary explaining overall site security for a non-tech owner.",
  "findings": [
    {
      "title": "Plain English title (e.g., 'Customer Privacy Risk' instead of 'Cross-Site Scripting')",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "what_is_it": "Simple 1-2 sentence explanation without tech jargon",
      "business_risk": "Why this matters to their business (e.g., reputational damage, customer data theft)",
      "how_to_fix": "Clear non-technical action step or exact copy-paste note for their web developer",
      "raw_technical_name": "Original scanner tool or vulnerability name"
    }
  ]
}

Ensure all JSON strings are properly escaped. Do not include markdown code block backticks if possible, or wrap in valid JSON.
Be concise, factual, and supportive.
"""


def _build_payload(state: dict) -> dict:
    return {
        "target_url": state.get("url"),
        "recon": state.get("recon"),
        "nuclei_results": state.get("nuclei_results"),
        "zap_results": state.get("zap_results"),
        "nikto_results": state.get("nikto_results"),
        "wapiti_results": state.get("wapiti_results"),
        "wpscan_results": state.get("wpscan_results"),
        "ffuf_results": state.get("ffuf_results"),
    }


def _local_summary(state: dict) -> str:
    """Free, offline fallback: no API call, just counts and lists findings."""
    lines = ["# Scan Summary (local, no AI -- free mode)\n"]
    lines.append(f"**Target:** {state.get('url')}\n")

    recon = state.get("recon") or {}
    lines.append("## Recon")
    lines.append(f"- Status code: {recon.get('status_code')}")
    lines.append(f"- Server header: {recon.get('server_header')}")
    lines.append(f"- Detected tech: {recon.get('tech_hints') or 'none detected'}")
    if recon.get("error"):
        lines.append(f"- Recon error: {recon['error']}")
    lines.append("")

    def section(title, results, key, count_fn=len):
        lines.append(f"## {title}")
        if not results:
            lines.append("- No data (node may not have run)")
        elif results.get("error"):
            lines.append(f"- Error: {results['error']}")
        elif results.get("skipped"):
            lines.append(f"- Skipped: {results.get('reason', 'n/a')}")
        else:
            items = results.get(key)
            n = count_fn(items) if items else 0
            lines.append(f"- {n} finding(s) reported")
            if items and isinstance(items, list):
                for item in items[:10]:
                    if isinstance(item, dict):
                        name = (item.get("info", {}).get("name")
                                 or item.get("name") or item.get("alert")
                                 or item.get("url") or str(item)[:100])
                    else:
                        name = str(item)[:100]
                    lines.append(f"  - {name}")
                if n > 10:
                    lines.append(f"  - ... and {n - 10} more (see raw appendix below)")
        lines.append("")

    section("Nuclei", state.get("nuclei_results"), "findings")
    section("ZAP (passive baseline)", state.get("zap_results"), "alerts")
    section("Nikto", state.get("nikto_results"), "findings")
    section("Wapiti", state.get("wapiti_results"), "findings")
    section("WPScan", state.get("wpscan_results"), "findings")
    section("ffuf (directory discovery)", state.get("ffuf_results"), "findings")

    lines.append("---")
    lines.append(
        "_This is a mechanically generated summary (counts + names only), "
        "not an AI analysis. Set ANTHROPIC_API_KEY or GEMINI_API_KEY in .env "
        "for a written, severity-ranked writeup with remediation guidance._"
    )
    return "\n".join(lines)


def _claude_summary(state: dict, api_key: str) -> str:
    from anthropic import Anthropic
    client = Anthropic(api_key=api_key)

    payload = _build_payload(state)
    user_message = (
        "Here is the raw scan data as JSON:\n\n"
        f"{json.dumps(payload, indent=2)[:15000]}\n\n"
        "Write the report as described in your instructions."
    )

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    text_parts = [block.text for block in response.content if block.type == "text"]
    return "\n".join(text_parts)


def _gemini_summary(state: dict, api_key: str) -> str:
    """
    Uses Google's free-tier Gemini API. Sign up (no card required) at
    https://aistudio.google.com, generate a key, put it in .env as
    GEMINI_API_KEY. Free tier covers this use case comfortably.
    """
    import google.generativeai as genai

    genai.configure(api_key=api_key)
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    model = genai.GenerativeModel(model_name, system_instruction=SYSTEM_PROMPT)

    payload = _build_payload(state)
    user_message = (
        "Here is the raw scan data as JSON:\n\n"
        f"{json.dumps(payload, indent=2)[:15000]}\n\n"
        "Write the report as described in your instructions."
    )

    response = model.generate_content(
        user_message,
        request_options={"timeout": 30},
    )
    return response.text


def _local_summary_json(state: dict) -> dict:
    """Free, offline fallback structured dict if no AI API key is set."""
    nuclei_count = len((state.get("nuclei_results") or {}).get("findings") or [])
    zap_count = len((state.get("zap_results") or {}).get("alerts") or [])
    total = nuclei_count + zap_count

    safety_rating = "SAFE" if total == 0 else ("NEEDS_ATTENTION" if total < 5 else "CRITICAL")
    score = max(20, 100 - (total * 15))

    findings = []
    if nuclei_count > 0:
        findings.append({
            "title": "Outdated Software & Configuration Vulnerabilities",
            "severity": "HIGH",
            "what_is_it": f"We found {nuclei_count} automated security warnings on your web server.",
            "business_risk": "Attackers could potentially target known software flaws to access website data.",
            "how_to_fix": "Ask your web administrator to update server software and security patches.",
            "raw_technical_name": "Nuclei Findings"
        })
    if zap_count > 0:
        findings.append({
            "title": "Missing Web Protection Headers",
            "severity": "MEDIUM",
            "what_is_it": f"Your web server is missing {zap_count} standard security protection headers.",
            "business_risk": "Browsers loading your website won't have standard privacy and anti-tampering rules enabled.",
            "how_to_fix": "Add standard HTTP security headers (HTTPS, Content-Security-Policy) to your web host configuration.",
            "raw_technical_name": "OWASP ZAP Baseline Alerts"
        })

    if not findings:
        findings.append({
            "title": "All Standard Checks Passed",
            "severity": "INFO",
            "what_is_it": "No obvious automated vulnerability alerts were triggered.",
            "business_risk": "Your website appears well-configured for standard security baseline checks.",
            "how_to_fix": "Keep server software and plugins updated regularly.",
            "raw_technical_name": "Clean Automated Scan"
        })

    return {
        "safety_rating": safety_rating,
        "business_impact_score": score,
        "voice_summary": f"Scan completed for {state.get('url')}. We found {total} items that need your attention. Overall your site rating is {safety_rating}. Click View Details to read the full report.",
        "executive_summary": f"Your security scan completed with an overall status of {safety_rating}. A total of {total} items were flagged by automated tools.",
        "findings": findings
    }


def summarize_node(state: dict) -> dict:
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    gemini_key = os.getenv("GEMINI_API_KEY")

    raw_summary = ""
    parsed_json = None

    try:
        if anthropic_key:
            raw_summary = _claude_summary(state, anthropic_key)
        elif gemini_key:
            raw_summary = _gemini_summary(state, gemini_key)
        
        if raw_summary:
            # Clean possible markdown json fences
            cleaned = raw_summary.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            parsed_json = json.loads(cleaned.strip())
    except Exception as e:
        print(f"AI summarization exception: {e}")

    if not parsed_json:
        parsed_json = _local_summary_json(state)

    state["summary_json"] = parsed_json
    state["summary"] = parsed_json.get("executive_summary", "")
    return state