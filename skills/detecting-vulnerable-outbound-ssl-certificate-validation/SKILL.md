---
name: detecting-vulnerable-outbound-ssl-certificate-validation
description: >-
  Detecting disabled TLS certificate validation in outbound requests (InsecureSkipVerify, verify=False, rejectUnauthorized:false). Covers language-specific sinks, mass-exposure impact, and remediation.
---

# SKILL: Detecting disabled TLS certificate validation in outbound requests (InsecureSkipVerify, verify=False, rejectUnauthorized:false). Covers language-specific sinks, mass-exposure impact, and remediation.

> **AI LOAD INSTRUCTION**: Load when auditing code or containers for disabled outbound TLS verification, which enables MITM on all outbound connections (API calls, webhooks, dependency fetches). Covers per-language detection patterns and real impact.

## 0. RELATED ROUTING
- [detecting-weak-tls-cipher-suites-tls-downgrade](#) for transport-layer weaknesses
- [detecting-expired-or-self-signed-certificate-misconfiguration](#) for cert lifecycle
- [detecting-supply-chain-container-image-backdoor-triage](#) for image-level triage

## 1. WHY IT MATTERS MORE THAN IT LOOKS

Disabled verification is not "a low-severity finding." If any app disables outbound cert validation, every outbound TLS connection is MITM-able — including ones carrying API keys, cloud tokens, or webhook secrets. In a container that also pulls images or talks to a cloud metadata endpoint, the blast radius is large.

## 2. LANGUAGE DETECTION PATTERNS

```bash
rg -n "InsecureSkipVerify\s*:\s*true"            # Go
rg -n "verify\s*=\s*False"                        # Python requests
rg -n "rejectUnauthorized\s*:\s*false"            # Node
rg -n "CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)"     # PHP cURL
rg -n "TrustManager|X509TrustManager|HostnameVerifier"  # Java custom trust
rg -n "ServicePointManager|ServerCertificateValidationCallback" # .NET
```

Also grep for ad-hoc fixes: `ssl._create_unverified_context`, `setDefaultHostnameVerifier`, `TrustAllCerts`, `trust: false`.

## 3. IMPACT ASSESSMENT

Ask what the app sends outbound: cloud API calls (token exfil on MITM), webhook POSTs (payload integrity), package/artifact downloads (supply-chain), or telemetry (PII leak). Rank severity by that, not by the pattern alone.

## 4. CONFIRM (Authorized Only)

On a system you control, run a local MITM proxy with a self-signed CA and observe whether the client accepts a forged certificate. On third-party systems, do not MITM — report the code/config evidence.

## 5. REMEDIATION

Remove the skip; use the system trust store; for genuine pinning needs use proper pinning (HPKP-style or library pinning), not blanket disable. In containers, mount the CA bundle and set `SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS`.

## Sources
- CWE-295: https://cwe.mitre.org/data/definitions/295.html
- Go crypto/tls docs: https://pkg.go.dev/crypto/tls#Config
- Node TLS docs: https://nodejs.org/api/tls.html
