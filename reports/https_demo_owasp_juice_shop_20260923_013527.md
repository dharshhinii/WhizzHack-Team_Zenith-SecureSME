# Security Scan Report

**Target:** https://demo.owasp-juice.shop

**Generated:** 2026-09-23T01:35:27.638372

---

# Scan Summary (local, no AI -- free mode)

**Target:** https://demo.owasp-juice.shop

## Recon
- Status code: 503
- Server header: Heroku
- Detected tech: none detected

## Nuclei
- Error: nuclei not found. Install it or set NUCLEI_PATH in .env

## ZAP (passive baseline)
- Error: zap-baseline.py not found. Install ZAP or set ZAP_BASELINE_PATH in .env

## Nikto
- Error: nikto not found. Install it or set NIKTO_PATH in .env

## Wapiti
- Error: wapiti not found. Install it or set WAPITI_PATH in .env

## WPScan
- Skipped: WordPress not detected

## ffuf (directory discovery)
- Error: ffuf not found. Install it or set FFUF_PATH in .env

---
_This is a mechanically generated summary (counts + names only), not an AI analysis. Set ANTHROPIC_API_KEY or GEMINI_API_KEY in .env for a written, severity-ranked writeup with remediation guidance._

---

## Raw Data Appendix

### Recon
```json
{'status_code': 503, 'server_header': 'Heroku', 'tech_hints': [], 'error': None}
```

### Nuclei
```json
{'findings': [], 'error': 'nuclei not found. Install it or set NUCLEI_PATH in .env'}
```

### ZAP
```json
{'alerts': [], 'error': 'zap-baseline.py not found. Install ZAP or set ZAP_BASELINE_PATH in .env'}
```

### Nikto
```json
{'findings': [], 'error': 'nikto not found. Install it or set NIKTO_PATH in .env'}
```

### Wapiti
```json
{'findings': {}, 'error': 'wapiti not found. Install it or set WAPITI_PATH in .env'}
```

### WPScan
```json
{'skipped': True, 'reason': 'WordPress not detected'}
```

### ffuf
```json
{'findings': [], 'error': 'ffuf not found. Install it or set FFUF_PATH in .env'}
```
