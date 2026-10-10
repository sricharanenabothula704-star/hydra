# : From Recon to RCE — Hunting React2Shell (CVE-2025-55182)
- Source: (Dec 11, 2025) — infosecwriteups.com
- CVSS 10.0: Unauthenticated RCE in React Server Components

## What is React2Shell?
- CVE-2025-55182: Critical vulnerability in React Server Components (RSC)
- CVSS 10.0 — maximum severity
- Affects React versions 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Impacts Next.js App Router, Vite, and other bundlers
- Unauthenticated Remote Code Execution via crafted Flight protocol requests

## Discovery via Asset Reconnaissance
### Shodan/ZoomEye/FOFA
```bash
# Shodan: React/Next.js servers
http.body:"react.production.min.js" || http.body:"React.createElement(" || \
  http.html:"React Router" || app:"React.js"

# FOFA
app="NEXT.JS" || app="React"

# For specific target domains, include hostname
http.body:"react.production.min.js" hostname:"target.com"
```

### CT Log Monitoring for Fresh Targets
```bash
# Monitor new certs, then filter for React/Next.js tech
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | \
  httpx -silent -td | grep -i "react\|next"
```

## Detection
```bash
# Check for RSC endpoints
curl -s -X POST "https://target.com/_next/data/..." -H "Content-Type: text/plain"
curl -s -X POST "https://target.com/api/..." -H "Content-Type: text/plain"

# Browser extension: mr RSC_Detector (checks if site is affected)
```

## WAF Bypass for React2Shell
- Alter payload structure, encoding, and transport behavior
- Signature-based filtering bypass via:
  - Multipart/form-data encoding
  - Chunked transfer encoding
  - Payload splitting across multiple chunks
  - Unicode/encoding transformations

## Impact
- Execute arbitrary JavaScript on the server
- Access environment variables (DB credentials, API keys)
- Full infrastructure compromise in cloud environments
- CVSS 10.0: No authentication required, no user interaction

## Safe Testing
- Use TryHackMe lab for practice (vulnerable React/Next.js setup)
- Always test responsibly with minimal exploitation
- Document every step for clear, high-impact bug bounty reports

## Key Takeaways
1. Use Shodan/ZoomEye/FOFA to find React/Next.js targets at scale
2. CT log monitoring catches fresh vulnerable deployments
3. WAF bypass techniques are often needed against protected targets
4. RCE through RSC deserialization — craft Flight protocol payloads
5. Document cost/impact clearly for higher bounties
