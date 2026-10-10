# : Mastering Origin IP Discovery Behind WAF — 11+ Methods
- Source: (Dec 30, 2024) — infosecwriteups.com
- Complete methodology to find origin IPs behind Cloudflare, Akamai, AWS WAF, etc.

## Why Origin IP Discovery?
The most effective WAF bypass: completely circumvent the WAF by attacking the origin server directly. If you find the real IP, all WAF rules are irrelevant.

## Method 1: DNS Historical Records (SecurityTrails)
```bash
# View historical DNS records
https://securitytrails.com/domain/target.com/dns
# Export A records — find IPs used BEFORE WAF was deployed
```

## Method 2: Shodan Dorks
```bash
# Search by certificate Common Name
shodan search "ssl.cert.subject.CN:target.com" --fields ip_str,port,org

# Search all certificate fields (broader)
shodan search "ssl:target.com"
```

## Method 3: Censys
Search for certificates → click "Explore" → "IPv4 Hosts"
Collect all associated IPs. SAN fields more reliable than CN.

## Method 4: FOFA
```bash
# Search by domain, filter by favicon hash
# Get favicon hash first
# Then search: icon_hash="FAVICON_HASH"
```

## Method 5: ZoomEye
```bash
# Enter domain, search, filter by favicon hash
# Then filter by IPv4 for clean results
```

## Method 6: Favicon Hash
```bash
# Get favicon URL from page source or curl
curl -sI https://target.com/favicon.ico | grep "location"
# Hash it, search across all platforms
```

## Method 7: viewdns.info IP History
```bash
https://viewdns.info/iphistory/?domain=target.com
# Lists all historical IPs — test each one
```

## Method 8: SPF Records
```bash
# Check SPF records for authorized IPs
dig txt target.com | grep "v=spf1"
nslookup -type=txt target.com | grep "spf"
```

## Method 9: VirusTotal
```bash
# Check domain report for IP resolutions
https://www.virustotal.com/gui/domain/target.com/relations
```

## Method 10: AlienVault OTX
```bash
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns"
```

## Method 11: Subdomain Enumeration for Origin Candidates
Subdomains not behind WAF: dev, stage, origin, mail, direct, ww1, ww2, admin, api
```bash
subfinder -d target.com | httpx -silent -ip | grep -v "cloudflare\|akamai\|fastly"
```

## Method 12: Email Headers Analysis
Send email to a non-existent address at target.com, inspect SMTP headers for origin IP:
- Return-Path header
- Received header chain
- X-Originating-IP header

## Validation
```bash
# For each candidate IP, test with Host header
curl -k -H "Host: target.com" https://CANDIDATE_IP/
curl -k -H "Host: target.com" https://CANDIDATE_IP/ -I

# Check if response matches the real site
# Compare: title, server header, response body hash
```

## Tools
```bash
# EvilWAF: automated origin hunting
python3 evilwaf.py -t https://target.com --auto-hunt

# CloudFlair: Cloudflare-specific origin discovery
python3 cloudflair.py target.com

# OriginIP: multi-source origin discovery tool
python OriginIP.py -u https://target.com
```

## Key Tips
- SAN (Subject Alternative Name) fields are more reliable than CN
- Historical DNS is most reliable (pre-WAF IPs)
- Always verify candidates with Host header forging
- 403 ≠ wrong IP — it means you found something but need more headers
- Subdomain IPs often share network ranges with origin
