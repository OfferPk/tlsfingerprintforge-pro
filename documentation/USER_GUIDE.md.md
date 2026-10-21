\# TLSFingerprintForge Pro \- User Guide & Integration Manual

\#\# 1\. Quick Start

\#\#\# Web Studio (100% Client-Side)  
1\. Open \`source-code/index.html\` in any web browser.  
2\. Select a client TLS profile preset:  
   \- \*\*Chrome 124 Genuine (A+)\*\*: Legitimate browser with GREASE, ALPN h2, and 15+ modern ciphers.  
   \- \*\*Python Requests Scraper (F)\*\*: Automation client with default OpenSSL ciphers and no ALPN.  
   \- \*\*Masquerading Scraper (Spoofed UA) (F)\*\*: Sneaky bot forging Chrome User-Agent with minimal TLS handshake.  
3\. Review the \*\*JA4 Fingerprint\*\* and \*\*JA3 Hash\*\* metrics.  
4\. If a mismatch is present (e.g. Chrome User-Agent with Python TLS stack), the studio immediately triggers a high-visibility \*\*HIGH-CONFIDENCE MASQUERADING DETECTED\*\* banner.  
5\. Review the \*\*10-Point Zero-Trust Scorecard\*\* to inspect which criteria passed or failed.  
6\. Copy ready-to-deploy mitigation rules from the \*\*Multi-WAF Synthesizer\*\* for \*\*Cloudflare WAF\*\*, \*\*AWS WAF v2\*\*, \*\*Nginx\*\*, \*\*HAProxy\*\*, or \*\*ModSecurity CRS\*\*.

\---

\#\# 2\. CLI Tool Usage (\`tlsfingerprint-cli.py\`)

The standalone Python CLI requires zero external dependencies and runs on Python 3.8+.

\#\#\# 2.1 Calculating JA4 and JA3 Fingerprints  
\`\`\`bash  
python3 build/tlsfingerprint-cli.py fingerprint \--preset presets/chrome124-macos-legitimate.json  
\`\`\`  
Output:  
\`\`\`json  
{  
  "ja4": "t13d1515h2\_8daaf6152771\_fdac44d73837",  
  "ja3\_hash": "b32309a26951912be7dba376398abc3b",  
  "ja3\_raw": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"  
}  
\`\`\`

\#\#\# 2.2 Matching a Fingerprint Against Known Bot Signatures  
\`\`\`bash  
python3 build/tlsfingerprint-cli.py match \--ja3 "9a2c611c7c2c5b92c96b691a1259b878"  
\`\`\`  
Output:  
\`\`\`json  
{  
  "id": "python\_requests",  
  "name": "Python Requests 2.x / urllib3",  
  "category": "SCRAPER",  
  "ja4\_prefix": "t13d080700",  
  "ja3\_hash": "9a2c611c7c2c5b92c96b691a1259b878",  
  "is\_bot": true,  
  "is\_malicious": false  
}  
\`\`\`

\#\#\# 2.3 Running Zero-Trust Bot Defense Audit with Strict CI/CD Gating  
\`\`\`bash  
\# Legitimate browser \-\> Exits code 0  
python3 build/tlsfingerprint-cli.py audit \--preset presets/chrome124-macos-legitimate.json \--strict

\# Automated scraper \-\> Exits code 1 (Gate Triggered)  
python3 build/tlsfingerprint-cli.py audit \--preset presets/python-requests-scraper.json \--strict  
\`\`\`

\#\#\# 2.4 Synthesizing Cloudflare / AWS WAF Rules  
\`\`\`bash  
python3 build/tlsfingerprint-cli.py synthesize \--preset presets/python-requests-scraper.json \-f cloudflare  
\# Output:  
\# (cf.bot\_management.ja4 \== "t13d080700\_6aee0a5c6037\_7a239c5f797f" or cf.bot\_management.ja3\_hash \== "9a2c611c7c2c5b92c96b691a1259b878")  
\`\`\`

\---

\#\# 3\. DevSecOps CI/CD Integration (GitHub Actions)

Add this check to your API gateway or WAF rule repository to verify TLS client profiles and ensure automated testing suites do not commit bypassable signatures:

\`\`\`yaml  
name: TLS Bot Defense & Fingerprint Verification

on:  
  pull\_request:  
    paths:  
      \- 'waf/\*\*'  
      \- 'security/\*\*'

jobs:  
  tls-fingerprint-audit:  
    runs-on: ubuntu-latest  
    steps:  
      \- uses: actions/checkout@v4  
      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'  
      \- name: Run TLSFingerprintForge Strict Gate  
        run: |  
          python3 build/tlsfingerprint-cli.py audit \--preset presets/chrome124-macos-legitimate.json \--strict  
\`\`\`  
