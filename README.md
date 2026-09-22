# Web Security Scan Pipeline (LangGraph + Claude)

Runs recon → Nuclei → ZAP baseline → Claude-powered analysis → Markdown report,
against a URL you own or are authorized to test.

## Setup

1. Install Python 3.10+
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and add your Anthropic API key
4. Install the scanning tools separately (see "Installing scanners" below)
5. Run: `python main.py https://your-authorized-target.com`

## Installing scanners

**Nuclei:**
```
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```
Or download a prebuilt binary from:
https://github.com/projectdiscovery/nuclei/releases

**OWASP ZAP (baseline scan):**
Easiest via Docker:
```
docker pull zaproxy/zap-stable
```
Then set `ZAP_BASELINE_PATH` in `.env` to a wrapper script that calls the
Docker container (see zap.md in ZAP's docs for the exact docker run command),
or install ZAP desktop and use its bundled zap-baseline.py directly.

## What each node does

- `recon.py` — lightweight fingerprinting (server header, tech hints)
- `nuclei_scan.py` — runs Nuclei's CVE/misconfig templates, captures JSON
- `zap_scan.py` — runs ZAP's passive baseline scan (safe, non-intrusive)
- `summarize.py` — sends all raw findings to Claude for severity-ranked analysis
- `report.py` — writes the final report to `reports/<target>_<timestamp>.md`

## Important

Only run this against URLs you own or have explicit written authorization
to test. The script will prompt you to confirm this before every run.

The ZAP baseline scan is passive-only by design (safe for repeat automated
runs). Do NOT wire in active/aggressive scanners or exploitation tools
(sqlmap, Metasploit, etc.) without a human manually reviewing and approving
each step — that's intentionally left out of this pipeline.
