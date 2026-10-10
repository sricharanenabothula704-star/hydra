> **Companion deep-dive for `SKILL.md` in this directory.**
> Source research: "HTTP/1.1 Must Die: the desync endgame" (Kettle, Aug 2025) — Expect-based desync, 0.CL, and chunk-extension (TE.TE) techniques.

# MODERN DESYNC — 0.CL, EXPECT-BASED & CHUNK-EXTENSION ATTACKS

The 2025 endgame research proved desync variants are inexhaustible ("more desync attacks are always coming"). This file covers the post-2022 classes the base SKILL.md predates.

## 1. THE FAMILIES

| Class | Mechanism | Era |
|---|---|---|
| CL.TE / TE.CL | Classic header disagreement | 2005/2019 |
| H2.CL / H2.TE | HTTP/2 downgrade smuggling | 2021 |
| CL.0 | Backend ignores Content-Length entirely | 2022 |
| CSD | Client-side desync (browser as victim) | 2022 |
| TE.0 | Dechunking backends | 2024 |
| TE.TE chunk extensions | Obfuscated chunked framing via extension abuse | 2025 |
| **Expect-based** | `Expect: 100-continue` mishandling ("complexity bomb") | 2025 |
| **0.CL** | Zero-length CL vs body interpretation | 2025 |

## 2. EXPECT-BASED DESYNC

Frontends honoring `Expect: 100-continue` pause for an interim response; backends that don't may treat the paused stream differently → framing split.

```http
POST / HTTP/1.1
Host: target.com
Expect: 100-continue
Content-Length: 44

GET /admin HTTP/1.1
X-Ignore: x
```

Probe matrix: with/without Expect × CL/TE/chunked × interim-response timing. The "complexity bomb": stack Expect with ambiguous framing so one parser waits while the other proceeds.

## 3. CHUNK-EXTENSION OBFUSCATION (TE.TE revival)

Chunk extensions let you smuggle syntax past frontends that parse loosely:

```http
Transfer-Encoding: chunked
5;x=1
HELLO
0

```

Variants to fuzz: quoted extensions (`5;x="1;y=2"`), multiple `;` params, whitespace around `;`, extension-only lines, `chunked;ext` combined headers. A frontend accepting-but-forwarding malformed extensions while backend re-parses = desync.

## 4. 0.CL PATTERN

Zero-value Content-Length where one layer treats request as bodyless and another reads a body:

```http
POST / HTTP/1.1
Content-Length: 0
Content-Length: 44

GET /admin HTTP/1.1
Host: target.com
```
(Duplicate-CL differential — also test `CL: 0` + real body against endpoints ignoring bodies.)

## 5. DETECTION METHODOLOGY (safe)

1. Use timeout-differential probes first (does server wait for promised body?) — no poisoning risk
2. Confirm with self-contained payload pairs on fresh connections only
3. Never leave dangling partial requests on shared connections in production targets
4. Detection ≠ exploitation: report the desync class + one benign proof (captured `/admin` GET landing), stop there

## 6. DEFENSES (for reports)

Disable HTTP/1.1 reuse at proxy↔origin boundaries, reject duplicate/ambiguous framing headers outright, normalize chunk parsing centrally, migrate origins to HTTP/2+ internally.

## REFERENCES
- portswigger.net/research/http1-must-die (Aug 2025)
- "Funky chunks" TE.TE research (2025)
- PortSwigger http-request-smuggler (Burp extension) for lab-grade tooling
