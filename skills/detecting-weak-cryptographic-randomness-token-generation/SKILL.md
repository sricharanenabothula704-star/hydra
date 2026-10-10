---
name: detecting-weak-cryptographic-randomness-token-generation
description: >-
  Detecting weak randomness (Math.random, rand, mt_rand) used for security tokens, session IDs, nonces, and password resets. Covers predictability analysis, impact, and secure alternatives per language.
---

# SKILL: Detecting weak randomness (Math.random, rand, mt_rand) used for security tokens, session IDs, nonces, and password resets. Covers predictability analysis, impact, and secure alternatives per language.

> **AI LOAD INSTRUCTION**: Load when auditing token/nonce/session generation for use of non-cryptographic RNG (Math.random, rand(), mt_rand, random.random) which makes values predictable and forgeable. Covers detection patterns and safe replacement.

## 0. RELATED ROUTING
- [detecting-session-token-predictability-brute-force](#) for token predictability
- [detecting-weak-random-value-generation-tokens](#) for the adjacent check
- [detecting-password-reset-account-enumeration-timing](#) for reset-flow issues

## 1. INSECURE RNG SINKS

- JavaScript: `Math.random()` (not CSPRNG)
- PHP: `rand()`, `mt_rand()`, `uniqid()` (time-based)
- Python: `random.random()` (not `secrets`)
- Java: `java.util.Random` (not `SecureRandom`)
- Ruby: `Random.new` (not `SecureRandom`)
- .NET: `System.Random` (not `RandomNumberGenerator`)

These are fine for jitter/IDs, catastrophic for security tokens.

## 2. PREDICTABILITY IMPACT

- Math.random() state can be recovered from a few outputs -> predict password-reset tokens.
- mt_rand seeded by time can be brute-forced across the seed space.
- uniqid() is time-based and trivially guessable.

## 3. DETECTION

```bash
rg -n "Math\.random\(|uniqid\(|mt_rand\(|\brand\(" -g '*.{js,php,py,rb}'
rg -n "new Random\(|java\.util\.Random" -g '*.java'
rg -n "import random\b" -g '*.py'   # then check for random. vs secrets.
```

Then trace whether the value reaches a reset link, session ID, CSRF nonce, or API key.

## 4. CONFIRM

Do not brute-force real tokens. Static evidence + a data-flow trace from an insecure RNG to a token sink is sufficient to report.

## 5. REMEDIATION

Use a CSPRNG per language: Node `crypto.randomBytes`/`randomUUID`, PHP `random_bytes`/`random_int`, Python `secrets`, Java `SecureRandom`, Ruby `SecureRandom`, .NET `RandomNumberGenerator`. Use >=128 bits of entropy for tokens.

## Sources
- CWE-338: https://cwe.mitre.org/data/definitions/338.html
- CWE-330: https://cwe.mitre.org/data/definitions/330.html
- MDN crypto.randomUUID: https://developer.mozilla.org/en-US/docs/Web/API/Crypto/randomUUID
