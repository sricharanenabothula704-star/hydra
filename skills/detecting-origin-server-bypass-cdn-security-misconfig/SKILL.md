---
name: detecting-origin-server-bypass-cdn-security-misconfig
description: >-
  An origin reachable by direct IP or unproxied hostname skips the CDN's WAF, rate limiting, IP reputation, and DDoS scrubbing entirely.
---

# SKILL: An origin reachable by direct IP or unproxied hostname skips the CDN's WAF, rate limiting, IP reputation, and DDoS scrubbing entirely.

> **AI LOAD INSTRUCTION**: Load when assessing CDN-fronted applications for origin exposure during an authorized external review or WAF validation.

## 0. RELATED ROUTING
- [detecting-subdomain-takeover-dangling-dns-record](#) for the shared-DNS failure this pairs with
- [detecting-exposed-environment-file-secret-leak](#) for the assets usually reachable only on origin
- [detecting-exposed-monitoring-dashboard-public-access](#) for admin paths often unproxied

## 1. WHAT THE EDGE IS SUPPOSED TO BUY YOU

A CDN terminates TLS, applies a WAF, enforces rate limits, absorbs volumetric
attacks, and strips spoofed headers. All of that is bypassed by reaching the origin
directly. The origin hostname and IP are discoverable from historical DNS records,
`mail.` and `ftp.` subdomains that were never proxied, certificate transparency logs
listing SANs the edge does not use, leaked source code (hostnames in
configuration, `.env`, build artifacts), and the `origin.example.com` naming
convention. Once an attacker has the origin IP, every control you bought at the edge
is simply not in the path.

## 2. PASSIVE ORIGIN DISCOVERY

Everything here is passive DNS or CT lookups — no traffic reaches the origin:

```
dig +short origin.example.com
dig +short direct.example.com
dig +short mail.example.com
host -t CNAME www.example.com          # confirm which names the edge serves
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | grep -oE '[a-z0-9.-]+\.example\.com' | sort -u | head -30
```

CT logs are the highest-yield source: they list every certificate-issued name for
the domain, including `direct`, `origin`, `internal`, `staging`, and `*-legacy`
names the organization forgot to route through the CDN.

## 3. LOW-IMPACT BYPASS VERIFICATION

Compare responses between edge and origin. A successful bypass is shown by
*behavioural differences*, not by a 200 alone. Probe only a benign, static path.

```
curl -sI https://www.example.com/ | grep -iE 'server|cf-ray|x-cache|x-amz-cf|via'
curl -sIk -H 'Host: www.example.com' https://ORIGIN_IP/ | grep -iE 'server|cf-ray|x-cache|location'
```

Origin fingerprints that reveal a bypass: absence of `cf-ray`/`x-amz-cf-id`/
`x-cache`/`via` headers, a different `Server` value (nginx vs cloudfront), a
different TLS certificate issuer or subject, or an HTTP status that differs for the
same path. Also test that the edge's protections are genuinely absent rather than
merely invisible:

- Rate limiting: a handful of requests to a static path — do not run a load test.
- WAF: do not send attack payloads to confirm absence; absence of the WAF
  fingerprint headers plus a differing origin response is sufficient evidence.
- Origin management paths: `/admin/`, `/.env`, `/actuator/`, `/server-status` on the
  origin only, with HEAD requests.

## 4. CONFIRMING EDGE CONTROLS ARE EDGE-ONLY

The decisive test is comparing identical requests across both paths. Same status and
same body from the origin while the edge returns a block or a challenge means the
control lives only at the edge. Keep requests to a handful per path:

```
curl -s -o /dev/null -w 'edge  %{http_code}\n'  https://www.example.com/health
curl -s -o /dev/null -w 'origin %{http_code}\n' -H 'Host: www.example.com' https://ORIGIN_IP/health
```

## 5. REMEDIATION VERIFICATION

- Restrict the origin to accept traffic **only** from the CDN's published egress
  IP ranges (AWS CloudFront, Cloudflare, Akamai, Fastly), enforced at the origin
  firewall or security group. This is the only fix that actually works.
- Make the origin hostname resolve only to CDN edges — a private DNS zone or a
  split-horizon record — so it is not resolvable from the internet at all.
- Deny the origin on any port other than what the CDN needs.
- Rotate and reissue certificates so the origin is not identified by a unique
  fingerprint, and enable CAA.
- Alert on requests to the origin arriving from outside the CDN ranges.
- Remove legacy subdomains (`mail`, `cpanel`, `ftp`, `test`, `staging`) from DNS.

## 6. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test, and confirm that
origin-bypass testing is explicitly in scope — some organizations treat any traffic
to an origin outside the CDN as an attack. Work entirely from passive discovery:
CT logs, DNS history, and public records. Do not run load tests, rate-limit
bypass tests, or WAF evasion payloads against production; do not send SQLi or XSS
probes to the origin to prove the WAF is missing there, since a missed detection
becomes an incident. Do not scan origin IP ranges broadly — probe at most a small
number of specific hosts you identified passively. Never attempt to poison caches or
manipulate routing; report origin IPs and hostnames and let the owner close access.

## Sources
- CWE-693: https://cwe.mitre.org/data/definitions/693.html
- CWE-441: https://cwe.mitre.org/data/definitions/441.html
- OWASP Web Security Testing Guide (WAF/CDN): https://owasp.org/www-project-web-security-testing-guide/
