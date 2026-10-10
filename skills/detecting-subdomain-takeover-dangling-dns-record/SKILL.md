---
name: detecting-subdomain-takeover-dangling-dns-record
description: >-
  A CNAME or NS pointing at a deprovisioned third-party service lets anyone register the target resource and serve content under the victim's domain.
---

# SKILL: A CNAME or NS pointing at a deprovisioned third-party service lets anyone register the target resource and serve content under the victim's domain.

> **AI LOAD INSTRUCTION**: Load when reviewing DNS records for unclaimed SaaS dependencies, or validating dangling records before an external exposure assessment.

## 0. RELATED ROUTING
- [detecting-origin-server-bypass-cdn-security-misconfig](#) for the shared-DNS infrastructure trust failure
- [detecting-exposed-monitoring-dashboard-public-access](#) for SaaS panels often left claimable
- [detecting-cloudflare-worker-subdomain-takeover](#) for the platform-specific Dangling DNS variant

## 1. HOW A RECORD BECOMES CLAIMABLE

A subdomain CNAMEs to a provider-specific hostname that encodes a customer
identifier — `myapp.herokudns.com`, `xyz.wildcard.netlify.app`,
`team.s3.amazonaws.com`, a GitHub Pages `<user>.github.io`, an Azure site, or a
Tumblr/Surge/Shopify vanity hostname. Ownership of the third-party resource is
tracked by a matching entry in the provider's own account system. When the customer
cancels, the resource is freed but the DNS record remains — so the *next* person to
register that exact identifier on the provider claims the origin and inherits the
victim's hostname, cookies, and TLS certificate.

Detection is fundamentally a DNS fact-finding problem, not an exploitation problem.

## 2. PASSIVE ENUMERATION OF CANDIDATES

Enumerate records first; never touch the provider during enumeration. CNAME chains
toward third-party providers are the only ones that matter:

```
dig +short CNAME dev.example.com
dig +short CNAME support.example.com
host -t CNAME cdn.example.com
```

Records that CNAME to `*.github.io`, `*.herokudns.com`, `*.azurewebsites.net`,
`*.cloudfront.net`, `*.s3.amazonaws.com`, `*.netlify.app`, `*.vercel.app`,
`*.web.app`, `*.firebaseapp.com`, `*.pages.dev`, `*.surge.sh`, or `*.myshopify.com`
are takeover candidates. NS records delegating to an unconfigured nameserver, and
MX records pointing at a deprovisioned mail provider, are the same class.

## 3. PROVIDER FINGERPRINTING

The CNAME target identifies the provider with high confidence. Resolve one more
step to confirm the backend exists and is unattributed:

```
dig +short dev.example.com
dig +short myapp.herokudns.com
curl -sI https://dev.example.com | head -20
```

Fingerprints to recognize: Heroku's `no such app` page; Netlify/Vercel's
`Not Found` with a wildcard banner; GitHub Pages' 404 with `There's nothing here`;
S3's `NoSuchBucket` XML; Azure's 404. A `404` from the provider — as opposed to a
`200` with real content — is the candidate signal. A `200` means the resource is
still claimed by someone, which may be the victim or may already be the attacker.

## 4. NON-INVASIVE CLAIMABILITY VERIFICATION

Never register, claim, or create anything on a third-party provider during an
assessment. Instead verify from the provider's own public metadata:

- **SecurityTrails / DNS history** — shows whether the record ever resolved to a
  live CNAME and when it stopped.
- **Certificate Transparency** — a CT log entry for the subdomain without a
  matching live page indicates a torn-down resource.
- **Provider unauthenticated endpoints** — for example, the S3 REST API returns
  `NoSuchBucket` for a freed bucket, which is conclusive without claiming it.
- **Wayback Machine** — a previously captured page proves the mapping was real.

## 5. PRIORITIZATION

Rank by impact, not just by count. Highest: subdomains used for email (MX) or for
authentication, session cookies scoped to the parent domain, or anything covered by
a wildcard certificate. A takeover on `auth.example.com` permits full account
hijack; a takeover on an unused `old-dev.example.com` is housekeeping.

## 6. REMEDIATION VERIFICATION

- Remove the CNAME/NS record entirely, or repoint it to a service you control.
- Never wildcard a `*.dev.example.com` CNAME to a public SaaS platform — that
  hands every unmatched subdomain to whoever claims a matching identifier.
- Automate dangling-record detection in CI by diffing DNS against the inventory of
  active third-party dependencies.
- Invalidate or rotate any TLS certificate that covered the affected names.
- Audit provider accounts for orphaned resources that could be re-registered.

## 7. RESPONSIBLE TESTING

Only assess domains you own or are explicitly authorized to test. Detection here is
entirely passive — DNS queries, CT logs, and HTTP GETs. Never register a hostname
on a hosting provider, never claim a resource to prove takeover, and never modify
DNS records during testing: claiming the resource is itself the attack, and it can
displace legitimate content. Do not submit the dangling hostname to a public
"takeover scanner" service, which may claim it or report the data publicly. Verify
provider state through public APIs and CT logs instead.

## Sources
- CWE-404: https://cwe.mitre.org/data/definitions/404.html
- CWE-350: https://cwe.mitre.org/data/definitions/350.html
- MITRE ATT&CK T1583.001: https://attack.mitre.org/techniques/T1583/001/
