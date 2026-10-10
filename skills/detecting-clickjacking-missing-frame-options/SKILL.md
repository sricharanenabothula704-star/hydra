---
name: detecting-clickjacking-missing-frame-options
description: >-
  Detect clickjacking by finding pages that lack X-Frame-Options and frame-ancestors CSP, allowing a malicious site to iframe and overlay a victim into unintended clicks.
---

# SKILL: Detect clickjacking by finding pages that lack X-Frame-Options and frame-ancestors CSP, allowing a malicious site to iframe and overlay a victim into unintended clicks.

> **AI LOAD INSTRUCTION**: Load when auditing any authenticated, action-taking page (settings, payments, admin, account actions) for framing protection.

## 0. RELATED ROUTING
- [detecting-http-security-header-misconfiguration](#) for the full header-hygiene review this belongs to
- [clickjacking](#) for UI-redress variants like double-click and cursor-jacking
- [detecting-cors-preflight-misconfiguration-wildcard](#) for the sibling browser-boundary control

## 1. THE MECHANISM

Clickjacking needs only two things: the target page renders inside an `<iframe>` on another
origin, and the attacker overlays deceptive UI so the victim's clicks land on the framed page.
No JS on the target is required. Modern variants (clickjacking → CSRF chains, drag-and-drop
redress, cursor-jacking, file-upload jacking) make it dangerous even on pages with no obvious
"button" to steal.

Two independent defenses exist and the goal is to have at least one, ideally both:

- `X-Frame-Options: DENY` (or `SAMEORIGIN`) — legacy, broadly honored.
- `Content-Security-Policy: frame-ancestors 'none'` / `'self'` — modern, more expressive
  (allows whitelisting specific embedding partners).

## 2. DETECT MISSING PROTECTION

Check the response headers on the sensitive page directly:

```bash
curl -sI https://target/settings/billing | grep -iE 'x-frame-options|content-security-policy'
```

Absence of both headers on an authenticated, state-changing page is the finding. Note that
`X-Frame-Options: ALLOW-FROM` is obsolete and ignored by modern browsers — its presence is not
a mitigation.

## 3. PROVE FRAMING WORKS (CONTROLLED POC)

Confirm the page actually renders in a cross-origin iframe before concluding. Serve a local
harness from a domain you control and load only your own test account's page:

```html
<!-- poc.html served on your own origin -->
<html><body style="margin:0">
  <iframe src="https://target/settings/delete-account" style="width:400px;height:300px;border:2px solid red"></iframe>
  <div style="position:absolute;top:280px;left:10px;background:#ff0;padding:8px">Click here to win a prize</div>
</body></html>
```

Open `poc.html` in a browser while logged into the target **with your own account**. If the
iframe renders (rather than being blocked/refused) and sits under your overlay, the page is
frameable and the vulnerability is demonstrated.

## 4. WHERE TO LOOK FOR HIGH IMPACT

Frameability matters most on pages that perform irreversible actions without a strong
re-confirmation step:

- Account/profile changes, password change, email/phone change, MFA disable.
- Payment/billing confirmations, payout or transfer approval.
- Admin actions: role assignment, feature toggles, deletions.
- Any action gated only by "user is logged in" with no CSRF token or confirmation dialog.

A framed page with no state change (a public marketing page) is a hardening gap, not a serious
finding. Calibrate severity to what's clickable.

## 5. INTERACTION WITH CSRF TOKENS

A framed page protected by an anti-CSRF token is not fully safe: clickjacking can still make a
victim unknowingly click an element that is not itself a tokenized form (e.g. a link, a button
that JS-submits with an embedded token, or a step where the token is already in the DOM). So
"has CSRF protection" does not mean "not frameable", and the two fixes are complementary.

## 6. DETECTION & REMEDIATION

- Set `Content-Security-Policy: frame-ancestors 'none'` (or a specific partner allowlist) on
  every authenticated page; prefer this over X-Frame-Options for modern browsers.
- Optionally also send `X-Frame-Options: DENY` for legacy clients.
- Apply headers **globally** at the reverse proxy/CDN so new pages inherit them.
- Add defense in depth: re-authenticate or require an explicit typed confirmation for
  irreversible actions, so an unintended overlay click is not sufficient.
- Audit in CI: assert every HTML response carries a frame-ancestors or XFO directive.

## 7. RESPONSIBLE TESTING NOTE

Build and serve the PoC **only on a domain you control** and frame **only pages of your own
test account**; never frame a page that acts on a real user's session, and never attempt to
complete an irreversible action through the overlay — you do not need to. Do not publish the
PoC URL or embed the target in a public page that could be visited by others, and do not
target third-party sites. This is a read-only, non-destructive check: viewing the framed page
with your own session is sufficient evidence; clicking through to a real destructive control is
not. Respect any clickjacking testing that the site owner has asked to skip, and keep PoC
artifacts off shared/public infrastructure.

## Sources
- CWE-1021: https://cwe.mitre.org/data/definitions/1021.html
- PortSwigger Clickjacking: https://portswigger.net/web-security/clickjacking
- MDN CSP frame-ancestors: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors
- OWASP Clickjacking Defense Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
