---
name: detecting-hardcoded-credentials-mobile-binary
description: >-
  Find hardcoded API keys, tokens, and secrets inside Android and iOS application binaries.
---

# SKILL: Find hardcoded API keys, tokens, and secrets inside Android and iOS application binaries.

> **AI LOAD INSTRUCTION**: Load when reversing a mobile app you own or are authorized to assess for embedded credentials.

## 0. RELATED ROUTING
- [performing-android-app-static-analysis-with-mobsf](#) for automated APK scanning
- [reverse-engineering-ios-app-with-frida](#) for runtime instrumentation and key capture
- [detecting-api-secret-embedded-in-frontend-bundle](#) for the web-bundle equivalent

## 1. WHY MOBILE SECRETS LEAK

The binary ships to every device and is trivially reversible. Secret classes commonly found:

- Third-party API keys (Google Maps, Firebase, Sentry, Stripe, analytics, push)
- Cloud backend endpoints plus the API key used to call them directly
- Private signing/verification keys and shared HMAC secrets
- Decryption keys or IVs for locally stored "encrypted" data
- Hardcoded admin/test credentials or bypass flags (`if (isDebug) grantAll`)
- Private bundle IDs, team IDs, and internal hostnames that aid targeting

Everything must be considered public the moment the app ships.

## 2. ACQUIRE THE ARTIFACTS

For an app you own or are authorized to test:

```
# Android
apktool d app-release.apk -o apk_out
unzip -o app.apk -d apk_unz
jadx -d jadx_out app.apk

# iOS
unzip -o App.ipa -d ipa_out      # Payload/*.app/ contains the Mach-O
otool -L Payload/App.app/App     # loaded frameworks
```

Also inspect `assets/`, `res/raw/`, `lib/*/`, Swift/ObjC metadata, and any `.plist` config.

## 3. STATIC STRING SEARCH

```
cd apk_out
grep -rInE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_live_[0-9a-z]+' .
grep -rInE 'gh[pousr]_[0-9A-Za-z]{36}|SG\.[0-9A-Za-z_\-]{20,}\.' .
grep -rInE '(api|app|client|secret|private)[_-]?key["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']{12,}' .
grep -rInE 'https?://[a-z0-9.\-]*\.(internal|local|corp|test|staging)[^"'"'"']*' .
grep -rInE 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.' .   # embedded JWTs

# resource/binary values
aapt dump strings app.apk 2>/dev/null | grep -iE 'key|secret|token|passw'
strings -a Payload/App.app/App | grep -iE 'api[_-]?key|secret|BEGIN [A-Z ]*PRIVATE KEY'
```

Automated assist, run only on artifacts you are authorized to analyze:

```
gitleaks detect --no-git apk_unz
trufflehog filesystem apk_unz --only-verified
mobsf --unzip apk_out   # includes static secret scanning
```

## 4. RUNTIME CONFIRMATION

A string match is only a finding if it authenticates somewhere. Use your own test backend or a
vendor sandbox account.

```
# Frida: watch what leaves the app (own device/emulator, own app build)
frida -U -f com.example.app -l trace-out.js --no-pause
# in trace-out.js, log URL + Authorization header for HTTPS calls only, redact values

# Android: confirm the key is actually sent
adb shell am start -n com.example.app/.ui.MainActivity
adb logcat | grep -iE 'apikey|authorization'
```

For a suspected backend key, make one benign authenticated call to a read-only endpoint on
your own sandbox tenant and record the result.

## 5. OBFUSCATION CHECKS

- Base64/hex constants decoded at runtime: `Base64.decode(`, `Data(contentsOf:)`
- Split strings and char arrays reassembled in code (`"AI" + "za"`)
- JNI/native `.so` or C++ symbols holding keys rather than the Java/Kotlin layer
- ProGuard/R8 renaming (keys survive; only names change)
- Encrypted assets with the key stored beside them (`CFBundleURLTypes`, `Info.plist`)

## 6. REMEDIATION

1. Remove all secrets from the app; rotate any that shipped.
2. Proxy privileged operations through your backend; the app authenticates to you, not the vendor.
3. Use per-user, short-lived, audience-scoped tokens issued after server-side authentication.
4. Keep signing keys in the platform keystore/Keychain or an attestation-gated service.
5. Add secret scanning to CI on the release pipeline and fail the build on matches.

## 7. RESPONSIBLE TESTING

Only analyze binaries you own, built from your own source, or have written authorization to
assess. Validate suspected credentials only against your own sandbox, tenant, or vendor trial
account. Never use a discovered key to reach third-party data, never re-share extracted secrets
outside the authorized report, and prefer reporting over exploiting.

## Sources
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-321: https://cwe.mitre.org/data/definitions/321.html
- OWASP Mobile Top 10 M9: https://owasp.org/www-project-mobile-top-10/
- OWASP MASTG: https://mas.owasp.org/MASTG/
