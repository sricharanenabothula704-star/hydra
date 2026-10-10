---
name: detecting-cloudflare-worker-subdomain-takeover
description: >-
  Detecting Cloudflare Worker, Pages, and workers.dev subdomain takeover through dangling CNAME/NS records and unclaimed routes. Covers DNS enumeration, fingerprinting the Cloudflare error signature, safe confirmation, and record hygiene to prevent re-occurrence.
---

# SKILL: Detecting Cloudflare Worker, Pages, and workers.dev subdomain takeover through dangling CNAME/NS records and unclaimed routes. Covers DNS enumeration, fingerprinting the Cloudflare error signature, safe confirmation, and record hygiene to prevent re-occurrence.

> **AI LOAD INSTRUCTION**: Load when you need to find subdomains pointing at Cloudflare Workers, Pages, or workers.dev endpoints where the backing project/route may be unclaimed or deleted. Covers passive DNS enumeration, Cloudflare fingerprinting, and takeover confirmation.

## 0. RELATED ROUTING
- [subdomain-takeover-detection-and-prevention](#) for the general dangling-DNS class
- [dns-recon-and-subdomain-enumeration](#) for subdomain discovery
- [discovering-shadow-api-endpoints-on-clouds](#) for orphan/unreferenced asset discovery
- [hardening-cdn-and-dns-configuration](#) for preventive controls

## 1. THE TAKEOVER PATTERN

A subdomain is claimable when its DNS still points at a provider resource whose owning slot is free. For Cloudflare this happens most often with:

- **CNAME to `*.workers.dev`** where the Worker route was deleted but the record remains — anyone can register that `workers.dev` name and serve content on your subdomain.
- **CNAME to `*.pages.dev`** for a deleted Pages project.
- **CNAME to a Cloudflare load balancer / Spectrum** target that no longer exists.
- **Deprecated CNAME flattening** where an A record resolves through a removed proxied hostname.

Because the record still points at Cloudflare, the subdomain serves Cloudflare-branded content or an error — which is the fingerprint.

## 2. PASSIVE DNS ENUMERATION

```bash
# Enumerate CNAMEs pointing into Cloudflare-owned namespaces
subfinder -d example.com -silent | dnsx -silent -cname -resp-only -o cnames.txt
dnsx -silent -cname -recon -silent -o cname_full.txt -d example.com

# Pull out Cloudflare worker/pages targets and any dangling NS
grep -iE 'workers\.dev|pages\.dev|cloudflare|workers' cname_full.txt
# Check NS records for subdomain delegation to Cloudflare nameservers
dig +short NS example.com
```

Any subdomain whose CNAME ends in `.workers.dev` or `.pages.dev` is a takeover candidate until proven otherwise.

## 3. FINGERPRINTING THE ERROR SIGNATURE

Request the subdomain and read Cloudflare's response code. Unclaimed/dead workers produce distinct signatures:

```bash
for host in $(grep workers.dev cnames.txt | cut -d' ' -f1); do
  echo "== $host"
  curl -sk -o /dev/null -w 'HTTP %{http_code}\n' "https://$host/"         # 404 from an unclaimed worker
  curl -sk "https://$host/" | grep -iE 'error code|1000|1014|workers\.dev|not found' | head -3
done
```

Key Cloudflare error codes for triage:
- **Error 1014** — CNAME Cross-User Banned: the classic dangling-Worker/R2/proxy signature.
- **Error 1000** — DNS points to prohibited IP / bad config.
- **Error 1003** — direct IP access not allowed (misrouted).
- **Error 1033** — Argo tunnel error; tunnel project deleted.

An unclaimed `workers.dev` returns Cloudflare's generic 404 with `workers.dev` branding. A claimed-but-broken worker returns your own app's error. The distinction tells you whether the name is still claimable.

## 4. SAFE CONFIRMATION

The safe, authorized confirmation is to observe, not to claim:

1. **Passive**: DNS resolves to a Cloudflare namespace and the HTTP response shows a Cloudflare error page or generic 404 — that alone establishes the dangling record. **Do not** attempt to register the `workers.dev` name on a third-party or unclaimed target; that's an actual takeover of someone else's namespace.
2. **Controlled canary (your own asset only)**: if the target is *your* orphaned project name, register the matching `workers.dev` in *your* account and confirm your content serves on the subdomain — this proves claimability without harming a third party.
3. **OOB (optional)**: for Cloudflare Access–protected routes, an unauthenticated 302 to the Access login vs. a public 200 distinguishes protected vs. dangling.

Never plant a marker page on a subdomain you don't control — that is an unauthorized content injection.

## 5. SCANNING AT SCALE

```bash
# nuclei takeover templates + http probe
httpx -l subs.txt -silent -status-code -cdn -probe -o probed.txt
nuclei -l subs.txt -t takeovers/*.yaml -silent
# dnsx CNAME + workers/pages filter, batched
dnsx -l subs.txt -silent -cname -resp | grep -iE 'workers\.dev|pages\.dev'
```

Run these on your own asset inventory (certificate transparency, DNS zone export, internal CMDB) — not against third-party domains.

## 6. RANKING / TRIAGE

Prioritize findings by business impact, not count:
- Subdomains pointing at orphaned **production/auth** services (login, admin, API, SSO, mail).
- Wildcard DNS + a CNAME pattern that would auto-claim (e.g., `*.api.example.com -> worker.dev`).
- Subdomains referenced in code/config but with dangling DNS — an attacker taking them over would intercept client traffic or capture credentials.
- CDN-fronted admin panels reachable via the dangling record.

## 7. PREVENTION & REMEDIATION

- **Delete dangling DNS records** promptly — the record is the vulnerability, not the worker.
- For Worker-backed subdomains, don't CNAME to a public `workers.dev` name. Instead attach the hostname to a Worker **route** on a Cloudflare-managed zone (or use Cloudflare DNS for the zone itself), so the record can't be claimed by an outside `workers.dev` registration.
- Prefer Cloudflare-managed DNS for all zones; avoid third-party CNAME chains that outlive the target.
- Add automated dangling-CNAME monitoring (periodic `dnsx`/nuclei scans + alerting on Cloudflare error codes).
- Track certificate transparency for unexpected subdomains appearing on your zones.
- Audit for orphaned-but-DNS-referenced hostnames in IaC/Terraform; decommission pipelines that leave records behind.
- Treat any confirmed takeover as an incident: rotate credentials that transited the subdomain, review TLS certs served on it, notify affected users.

## Sources
- https://developers.cloudflare.com/errors/error-codes/
- https://developers.cloudflare.com/workers/configuration/routing/routes/
- https://github.com/projectdiscovery/nuclei-templates (http/misconfiguration takeover templates)
- https://developers.cloudflare.com/workers/configuration/routing/git-repositories/