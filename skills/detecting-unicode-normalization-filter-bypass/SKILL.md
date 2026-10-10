---
name: detecting-unicode-normalization-filter-bypass
description: >-
  Detecting security-filter bypass via Unicode normalization, homoglyphs, and bidirectional text. Covers WAF/allowlist evasion, confusable usernames, and RTL override display spoofing.
---

# SKILL: Detecting security-filter bypass via Unicode normalization, homoglyphs, and bidirectional text. Covers WAF/allowlist evasion, confusable usernames, and RTL override display spoofing.

> **AI LOAD INSTRUCTION**: Load when a filter compares strings but doesn't normalize Unicode, or an allowlist (usernames, domains, file names) accepts confusable characters. Covers homoglyph bypass, full-width/compatibility forms, zero-width joiners, and bidi override tricks.

## 0. RELATED ROUTING
- [exploiting-cwe-79-cross-site-scripting-reflection-sinks](#) for filter-evasion context
- [detecting-idor-sequential-identifier-enumeration](#) for identifier handling
- [detecting-typosquatting-domains-with-dnstwist](#) for homoglyph domains

## 1. THE CLASS OF BYPASSES

- **Homoglyphs:** Cyrillic `а` (U+0430) looks like Latin `a`. A filter blocking "admin" misses "аdmin" and it may still render identically to a user.
- **Compatibility/full-width forms:** full-width Latin `ａｄｍｉｎ` normalizes (NFKC) to "admin" but bypasses byte-equality filters.
- **Zero-width/joiner injection:** inserting U+200B/U+200D inside a blocked word breaks substring matching while being visually invisible.
- **Bidirectional override (U+202E):** reverses the visual order of text, letting a file like `exe.txt` display as `txt.exe` — classic extension-spoofing.
- **Case-folding tricks:** dotted/dotless Turkish I, Kelvin sign `K` → normalizes to `k`.

## 2. WHERE IT MATTERS

- Username/display-name allowlists (impersonating "admin")
- Filename extension checks (`photo.png\u202Egpj` style display spoofing)
- Domain/email validation (homoglyph phishing)
- WAF keyword filters blocking "select"/"union" bypassed by full-width forms

## 3. SAFE TESTING

Test on a **throwaway account/system you control**. Create a test username with a homoglyph and see whether it's accepted where the ASCII version is blocked. Don't attempt to impersonate real users.

## 4. DETECTION & REMEDIATION

- Normalize to NFKC and case-fold **before** comparing/filtering.
- Restrict usernames to a safe charset or strip zero-width/bidi controls (reject, don't silently strip).
- Allowlist by code point, not rendered appearance; display a warning for confusables.
- For extensions, allowlist by decoded content type/magic bytes, never by displayed name.

## Sources
- CWE-1007 (insufficient visual distinction): https://cwe.mitre.org/data/definitions/1007.html
- Unicode UTS #39 normalization: https://www.unicode.org/reports/tr39/
- OWASP Input Validation: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
