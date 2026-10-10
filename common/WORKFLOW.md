# Practical Workflow for Fuzzing and Scanning (Mar 2026)


## The Core Pipeline

```
CHAOS → HTTPX → NAABU → NMAP + PARSERS → NUCLEI → FFUF
```

## Phase 1: Subdomain Discovery with Chaos

```bash
# Gather subdomains from CT logs, DNS PTR, TLS scans
chaos -d target.com -o subs.txt
# ~3,000 subdomains typically
```

**What it gives you**: Broad external attack surface before sending a single probe.

## Phase 2: Alive Hosts & Deduplication

### Probe with HTTPX
```bash
# Check live hosts + collect IPs
httpx-toolkit -l subs.txt -ip -silent -o live.txt

# Extract unique IPs (deduplicate)
httpx-toolkit -l subs.txt -ip -silent | sed -nE 's/.*\[([0-9.]+)\].*/\1/p' | sort -u > ip.txt
# ~379 unique IPs from ~3,000 subs typically
```

### CRITICAL: CDN/WAF Filtering
```bash
# Before scanning, check if IP belongs to Cloudflare/Akamai/Fastly
# Scanning CDN IPs is pointless — you hit edge servers, not origin
# You'll also get your IP banned fast

# Use -title flag to verify:
httpx-toolkit -l ip.txt -title -silent
# If title matches actual website → likely origin IP
# If shows generic CDN/WAF pages → skip it
```

**Key insight**: Most collected IPs will be CDN. Filter them out first.

## Phase 3: Port Scanning with Naabu

```bash
# Fast port scan with verification
naabu -l ip.txt -top-ports 100 -rate 1500 -verify -silent -o naabu.txt
```

**Why**: Scanning every port across thousands of subdomains is slow and noisy. Naabu on unique IPs with verification gives clean, verified open ports.

**Output**: Clean list of verified open ports — no wasted effort on filtered/closed services.

## Phase 4: Advanced Service Detection & Nmap Parsing

### Run Nmap with vuln scripts
```bash
# Using custom script
python3 ~/scripts/naabutonmap.py -i naabu.txt

# What it runs:
# nmap -sS -sV -sC --version-all --script vuln,default --open -T4 -Pn
```

### Parse Nmap output to readable HTML
```bash
# Convert XML to structured HTML report
# Tool: ernw/nmap-parse-output
./nmap-parse-output nmap-out/scan.xml html > scan.html
```

| Feature | Benefit |
|---------|---------|
| Host Summary | Quickly see which IPs have most exposure |
| Version Info | Identify "low hanging fruit" (outdated software) |
| Visual Layout | Easily spot high-value attack surfaces |

**What it reveals**: Service detection (Apache/Nginx/Redis), version fingerprinting, NSE vuln audits.

## Phase 5: Automated Vulnerability Scanning with Nuclei

```bash
# Scan live IPs for CVEs
cat ip.txt | nuclei -tags cve -bs 200

# Scan ALL discovered ports (including non-standard)
cat naabu.txt | nuclei -tags cve -bs 200
```

**Why Naabu output directly**: Many applications, admin panels, APIs, and sensitive files are hosted on non-standard ports. Don't just scan 80/443.

**Templates used**: CVEs, default credentials, misconfigurations, exposed tokens.

## Phase 6: Content Discovery & Fuzzing with FFUF

```bash
# Directory brute force + backup files + sensitive paths
# Using payloads repo
ffuf -w ip.txt:SUB -w payloads/backup_files_only.txt:FILE \
     -u https://SUB/FILE -mc 200 -rate 50 -fs 0 -c

ffuf -w naabu.txt:SUB -w payloads/backup_files_only.txt:FILE \
     -u https://SUB/FILE -mc 200 -rate 50 -fs 0 -c
```

**Payload sources**: any backup-file wordlist (e.g. from your fuzzing wordlist collection) — backup_files_only.txt

## Pro-Tips (Secrets)

### 1. Response Analysis Beyond Status Codes
```bash
# Don't just check 200 — analyze response size and word count
# A 200 OK might be a custom error page matching real page size
ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 0 -fw 0 -fc 404
```

### 2. Include Non-Standard Ports
```bash
# Use naabu port list in ffuf — vulns hide on unusual ports
ffuf -w naabu.txt:URL -w wordlist.txt:FILE -u https://URL/FILE
```

### 3. 403 Bypass is Gold
```bash
# 403 Forbidden often means you found something sensitive
# Always try 403 bypass techniques:
# - X-Forwarded-For: 127.0.0.1
# - X-Forwarded-Host: localhost
# - X-Real-IP: 127.0.0.1
# - X-Original-URL: /admin
# - X-Rewrite-URL: /admin
# - Add trailing slash: /admin/
# - Path traversal: /admin%2f
# - Double encoding: /%2561dmin
# - Case variation: /AdMiN
# - HTTP method override: POST with X-HTTP-Method-Override: GET
```

### 4. CDN/WAF Filtering is Mandatory
```bash
# Check before scanning ANY IP:
# - If cf-ray header → Cloudflare → likely not origin
# - If X-Sucuri-ID → Sucuri → skip
# - If X-Akamai-Transformed → Akamai → skip
# Verify with: httpx -title - if title matches, it's origin
```

## Full One-Liner Pipeline (Complete Workflow)

```bash
# Complete recon pipeline in one shot:
chaos -d target.com -o subs.txt && \
httpx-toolkit -l subs.txt -ip -silent | sed -nE 's/.*\[([0-9.]+)\].*/\1/p' | sort -u > ip.txt && \
httpx-toolkit -l ip.txt -title -silent | grep -vi "cloudflare\|akamai\|fastly" | awk '{print $1}' > origin_ips.txt && \
naabu -l origin_ips.txt -top-ports 100 -rate 1500 -verify -silent -o naabu.txt && \
python3 ~/scripts/naabutonmap.py -i naabu.txt && \
cat ip.txt | nuclei -tags cve -bs 200 && \
cat naabu.txt | nuclei -tags cve -bs 200 && \
ffuf -w naabu.txt:URL -w ~/payloads/backup_files_only.txt:FILE -u https://URL/FILE -mc 200 -rate 50 -fs 0
```

## Rate Limit Bypass Techniques (- May 2025)

### Common Rate Limit Mechanisms
1. **IP-Based**: Requests per IP within time frame
2. **User-Based**: Per authenticated user/API key
3. **Endpoint-Based**: Per specific route
4. **Global**: Total requests across all endpoints

### Bypass Techniques
| Technique | Method |
|-----------|--------|
| **IP Rotation** | Use proxy rotation / VPN / X-Forwarded-For |
| **Header Manipulation** | Add X-Forwarded-For with different IPs per request |
| **Cookie/Token Reset** | Clear cookies, get new rate limit bucket |
| **HTTP Method Change** | POST vs GET may have different limits |
| **Parameter Pollution** | Add dummy params to bypass endpoint-specific limits |
| **Distributed Attack** | Spread across multiple endpoints |
| **Timing** | Slow down to stay under threshold |
| **Race Condition** | Send all requests before rate limit kicks in |

## References
- Original article: Medium, "A Practical Workflow for Fuzzing and Scanning in Bug Bounty" (Mar 26, 2026)
- nmap-parse-output: github.com/ernw/nmap-parse-output
