---
name: xs-leaks
description: >-
  Cross-Site Leaks playbook. Use when hunting information-disclosure oracles that leak data cross-origin without XSS — response size/timing/ETag oracles, redirect leaks, connection-pool attacks, and frame-counting techniques.
---

# SKILL: XS-Leaks — Cross-Site Information Disclosure

> **AI LOAD INSTRUCTION**: XS-Leak techniques from 2025 research (two entries in PortSwigger Top-10 2025): Cross-Site ETag Length Leak, XSS-Leak cross-origin redirect leak via connection-pool prioritization, plus the classic oracle families. Side channels became a core exploitation primitive in 2025 — these bugs survive patches because they exploit browser/platform behavior, not app code.

## 1. CORE CONCEPT

An XS-Leak makes a victim's browser reveal cross-origin information to an attacker's page by observing *side effects* of authenticated requests: status codes, response sizes, timings, cache state, redirect targets. Same-Origin Policy blocks reading responses — but not measuring them.

```
Victim logged into target.com
Attacker page makes browser issue requests to target.com
Attacker measures: error vs success / fast vs slow / cached vs not / ETag length
→ Derives secret (is user admin? does file exist? what's their ID?)
```

## 2. ORACLE FAMILIES

### 2.1 Response Size Oracles
- **Cross-Site ETag Length Leak** (Top-10 2025 #6): `If-None-Match` + range/caching edge cases let an attacker compare ETag lengths cross-domain → leaks response-size differences (e.g., username length, record counts)
- Error pages differ in byte-length from success pages → measure via `performance.getEntries()` transferSize on same-site subdomains, or cache probing

### 2.2 Redirect Target Leaks
- **XSS-Leak** (Top-10 2025 #8): Chrome's connection-pool prioritization acts as an oracle leaking cross-origin redirect hostnames — attacker times which socket gets reused after a redirect chain
- Classic variants: `max-redirect` exhaustion errors, CSP `report-uri` leakage, referrer leakage on final hop

### 2.3 Cache Probing
```js
// Is URL cached? (victim previously visited/authed)
// 1. Prime: fetch resource with cache:'force-cache' from attacker context
// 2. Time a fetch with cache:'no-store' vs default — timing delta reveals hit/miss
// 3. CSS/JS resource timing via PerformanceObserver
new PerformanceObserver(l => console.log(l.getEntries()))
  .observe({type:'resource', buffered:true});
```

### 2.4 Frame Counting & ID Guessing
- Iframe `onload`/`onerror` counting: paginated search results render different frame counts per query → binary-search another user's data
- History.length deltas across navigations leak navigation counts

### 2.5 Timing Oracles
- Search endpoints: "found" results take measurably longer than "not found" → enumerate emails/usernames/tokens
- See `web-timing-attacks/SKILL.md` for server-side statistical methodology

## 3. HIGH-VALUE TARGETS

| Target pattern | Leakable question |
|---|---|
| `/search?q=` | Does value X exist for this user? |
| `/export?id=` / `/download?file=` | Does object/file exist? |
| OAuth/SAML flows | Where does the auth flow redirect (tenant/user enumeration)? |
| Admin panels behind auth | Is victim an admin? (frame counting on dashboard) |
| Token-bearing URLs in redirects | Partial token recovery via redirect-chain oracles |

## 4. EXPLOITATION SKELETON

```html
<!-- Attacker page: binary-search existence oracle via image onload/onerror -->
<img src="https://target.com/avatar/existing-user.png"
     onload="hit()" onerror="miss()">
<!-- Combine with fetch metadata + timing for robustness -->
<script>
async function timed(url){const t=performance.now();
  await fetch(url,{mode:'no-cors'});return performance.now()-t;}
</script>
```

Requirements: victim authenticated at target; attacker page can trigger cross-site requests (cookies SameSite=None/Lax-on-top-level); a measurable side-channel differential.

## 5. METHODOLOGY

1. Map unauthenticated-vs-authenticated behavioral deltas on the target (status, size, redirect count)
2. For each delta, ask: can I observe it cross-origin? (timing, frames, cache, errors)
3. Build the oracle; measure noise floor (≥100 samples, use median/percentiles)
4. Escalate: existence oracle → enumeration → PII extraction → report as info-leak chain

## 6. FALSE POSITIVE TRAPS

- Network jitter ≠ oracle — prove differential significance statistically
- SameSite=Lax cookies block most cross-site request contexts (top-level GET still works)
- Browser privacy features (partitioned caches) break classic cache probing on modern Chrome
- Report impact honestly: existence-oracle on non-sensitive data = Low/Info

## REFERENCES
- Top-10 2025 #6: "Cross-Site ETag Length Leak" (arkark)
- Top-10 2025 #8: "XSS-Leak: Leaking Cross-Origin Redirects" (babelo)
- xsleaks.dev — canonical technique index
