---
name: bug-bounty
description: Full bug bounty hunting methodology for web targets including recon, attack surface mapping, and vulnerability discovery
---

## Bug Bounty Methodology

### Phase 1: Reconnaissance
1. **Subdomain enumeration**: dig, sublist3r, crt.sh, certificate transparency
2. **DNS analysis**: Check for DNS leaks (private IPs in public DNS), zone transfers, CNAME records
3. **Technology fingerprinting**: Wappalyzer, curl headers, error pages
4. **Scope verification**: Confirm target is in-scope per program rules
5. **JS bundle extraction**: Download and analyze JavaScript for API endpoints, secrets, tokens

### Phase 2: Attack Surface Mapping
1. **API discovery**: Look for /api, /v1, /v2, /graphql, /swagger, /docs, /openapi.json
2. **Endpoint enumeration**: Common paths (/actuator, /.env, /.git, /admin, /health)
3. **Auth analysis**: JWT tokens, OAuth flows, API keys, TOTP mechanisms
4. **CORS testing**: Check for wildcard origins, credential reflection
5. **Subdomain takeover**: Check CNAME targets that don't resolve

### Phase 3: Vulnerability Discovery
1. **Information disclosure**: Exposed configs, debug endpoints, stack traces, directory listings
2. **Authentication bypass**: Default creds, missing auth, weak JWT, IDOR
3. **SSRF testing**: Open redirects, DNS rebinding, cloud metadata endpoints
4. **CORS misconfiguration**: Credential-enabled CORS with arbitrary origins
5. **Rate limiting**: Check for missing rate limits on auth/OTP endpoints

### Phase 4: Validation & Reporting
1. **PoC development**: Create clear, reproducible proof of concept
2. **Impact assessment**: Determine severity (Low/Medium/High/Critical)
3. **Report writing**: Clear steps to reproduce, screenshots, curl commands
4. **Responsible disclosure**: Submit via program platform only
