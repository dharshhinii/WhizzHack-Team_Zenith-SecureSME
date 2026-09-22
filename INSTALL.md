# Installing All Scanners

Run these on your own machine (not in this chat). Most are one-liners.

## 1. OWASP ZAP (already covered)
```
docker pull zaproxy/zap-stable
```

## 2. Nikto
```
git clone https://github.com/sullo/nikto
cd nikto/program
perl nikto.pl -h https://target.com
```
Or via package manager: `apt install nikto` (Debian/Kali) / `brew install nikto` (Mac)

## 3. Wapiti
```
pip install wapiti3 --break-system-packages
wapiti -u https://target.com
```

## 4. Arachni
Official project is archived; use a maintained community fork:
```
git clone https://github.com/Arachni/arachni
```
(Ruby-based, setup is heavier — check the fork's README for current build steps)

## 5. SQLmap
```
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py -u "https://target.com/page?id=1"
```

## 6. XSStrike
```
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt --break-system-packages
python xsstrike.py -u https://target.com
```

## 7. WPScan
```
gem install wpscan
wpscan --url https://target.com --api-token YOUR_FREE_TOKEN
```
Free API token (limited lookups/day): https://wpscan.com/api

## 8. Nuclei (already covered)
```
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## 9. ffuf
```
go install github.com/ffuf/ffuf/v2@latest
ffuf -u https://target.com/FUZZ -w wordlist.txt
```

## 10. wfuzz
```
pip install wfuzz --break-system-packages
wfuzz -u https://target.com/FUZZ -w wordlist.txt
```

## 11. Skipfish
Archived by Google but source still builds:
```
git clone https://github.com/spinkham/skipfish
cd skipfish && make
./skipfish -o output_dir https://target.com
```

## 12. W3af
```
git clone https://github.com/andresriancho/w3af.git
cd w3af
./w3af_console
```
(Python 2 legacy in places — most active alternative today is Nuclei/ZAP; install only if you specifically need its plugin set)

## 13. Vega
GUI tool, download the installer directly:
https://github.com/subgraph/Vega/releases
No CLI automation API — run manually, export results as XML/JSON.

## 14. Burp Suite Community Edition
GUI tool, download from:
https://portswigger.net/burp/communitydownload
Community edition has no automated scanner (that's Pro-only) — used for manual proxying/repeater/intruder work, not something to wire into an unattended pipeline.

---

## Which of these are CLI-scriptable (fit the pipeline) vs GUI-only (manual)

| Tool | Scriptable? | Notes |
|---|---|---|
| ZAP | ✅ | already in pipeline |
| Nuclei | ✅ | already in pipeline |
| Nikto | ✅ | added below |
| Wapiti | ✅ | added below |
| WPScan | ✅ | added below, conditional on WordPress detection |
| ffuf | ✅ | added below |
| Skipfish | ✅ | added below |
| W3af | ✅ (console mode) | added below |
| SQLmap | ✅ but **exploitative** | separate manual-confirm script |
| Commix | ✅ but **exploitative** | separate manual-confirm script |
| XSStrike | ✅ but semi-active (injects payloads) | separate manual-confirm script |
| Arachni | ⚠️ heavy setup | not wrapped — run standalone if needed |
| wfuzz | ✅ | same category as ffuf, ffuf is faster — add if you want both |
| Vega | ❌ GUI only | run manually |
| Burp Community | ❌ GUI only, no automated scan in free tier | run manually |
