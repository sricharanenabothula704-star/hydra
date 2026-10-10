---
name: web-timing-attacks
description: >-
  Web timing attack playbook. Use when measuring server-side processing time reveals secrets — blind injection confirmation, token/username enumeration, hidden route discovery, and statistical timing oracle methodology.
---

# SKILL: Web Timing Attacks

> **AI LOAD INSTRUCTION**: Timing side-channels as exploitation primitive (Kettle's 2024 research + Top-10 2025 trend: "side channels became a core exploitation primitive"). Covers single-packet attack methodology, statistical noise control, delay-based blind SQLi/command injection confirmation, and enumeration oracles that survive WAFs.

## 1. CORE CONCEPT

Server CPU time correlates with secrets: comparison loops exit early on mismatch, cache hits are faster than misses, heavy queries take longer. Measure precisely enough → read data you can't see.

```
if (secret.startsWith(guess)) { ...expensive work... }
→ guess correct = measurably slower response
```

## 2. WHY TIMING BEATS OTHER ORACLES

- Works when responses are IDENTICAL byte-for-byte (blind everything)
- Survives WAFs — no payload signatures, just latency
- Confirms blind SQLi/CMDi/SSTI where error+boolean channels are stripped

## 3. NOISE CONTROL (the whole discipline)

Naive timing fails in production. Mandatory controls:
1. **Warm the connection**: discard first N requests (JIT, TLS handshake, pool setup)
2. **Sample distributions**: ≥100 samples per hypothesis; compare medians/percentiles, NEVER means of small sets
3. **Single-packet attack**: send all probe variants back-to-back on one connection so queueing noise applies equally (Turbo Intruder / HTTP/2 multiplexing)
4. **Baseline subtraction**: measure an empty endpoint's jitter profile first; subtract
5. **Amplify**: force the expensive branch to run many times internally (e.g., `SLEEP(5)` vs deep pagination) until signal ≫ noise

## 4. ATTACK RECIPES

### 4.1 Blind Injection Confirmation
```sql
' AND (SELECT count(*) FROM information_schema.columns a,
      information_schema.columns b, information_schema.columns c)>0 AND '1'='1
-- cross join = deliberate CPU amplification; no SLEEP signature for WAFs
```

### 4.2 Enumeration Oracles
- Username reset flows: valid user + wrong password does hash-compare (slow); invalid user skips it → enumerate registered emails
- Token validation: early-exit string compare → recover token prefixes char-by-char (amplify with long tokens)

### 4.3 Hidden Route / Parameter Discovery
- Existing routes hit app logic (+ms); non-existent hit 404 handler only → discover unlinked admin routes by latency alone
- Hidden parameters: recognized params trigger extra processing even when response identical

## 5. METHODOLOGY

1. Identify candidate: same-response different-input pairs (or blind injection point)
2. Baseline: 100× empty/fastest variant → record median + p90 spread
3. Hypothesis testing: 100× each variant interleaved (not sequential — thermal/load drift)
4. Signal bar: delta > 3× baseline p90 spread AND reproducible across hours
5. Escalate existence-oracle → enumeration → extraction chain

## 6. FALSE POSITIVE TRAPS

- CDN/edge caching poisons measurements — bust cache per request, measure MISS paths
- Autoscaling cold-starts mimic signals — interleave hypotheses, never batch A-then-B
- Report impact honestly: timing oracles are Medium typically; chain to enumeration for High

## REFERENCES
- Kettle, "Web timing attacks made practical" (2024) + tooling (turbo-intruder)
- Top-10 2025 editor note: side-channel trend
