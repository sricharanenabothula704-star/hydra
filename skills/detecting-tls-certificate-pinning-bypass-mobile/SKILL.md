---
name: detecting-tls-certificate-pinning-bypass-mobile
description: >-
  Assess mobile certificate pinning strength across Android and iOS, validate trust coverage, and determine whether pinning can be defeated by userland hooks.
---

# SKILL: Assess mobile certificate pinning strength across Android and iOS, validate trust coverage, and determine whether pinning can be defeated by userland hooks.

> **AI LOAD INSTRUCTION**: Load when testing an authorized mobile application, evaluating a pinning implementation, or reviewing mobile release security gates.

## 0. RELATED ROUTING
- [performing-mobile-app-certificate-pinning-bypass](#) for the interception technique set
- [intercepting-mobile-traffic-with-burpsuite](#) for proxy workflow
- [analyzing-android-malware-with-apktool](#) for manifest and config review

## 1. WHY PINNING IS NOT A COMPLETE CONTROL

Certificate pinning blocks a proxy presenting a different certificate. It does not
protect against an attacker running code inside the application process, on the
same device, or holding the app's signing key. Treat it as defense in depth and
verify the trust configuration, not just its presence.

## 2. ANDROID PINNING TRUST SOURCES

Review `res/xml/network_security_config.xml` and inspect the bundled APK.

```bash
apktool d app.apk -o app_out
cat app_out/res/xml/network_security_config.xml
grep -rn 'networkSecurityConfig\|cleartextTraffic' app_out/AndroidManifest.xml
```

Rank configurations by strength: `android:debuggable="true"` in a release build
makes pins bypassable since the app trusts user CAs; `<certificates src="user"/>`
trusts any user-installed CA and defeats pinning entirely; `<certificates
src="system"/>` plus an explicit `<pin-set>` with `expiration` set is the strongest
practical configuration; and with no pin-set but OkHttp or Cronet configured
programmatically, audit the Java/Kotlin or native paths instead of XML.

Verify the pin digest is computed over the SubjectPublicKeyInfo (SPKI) leaf
certificate, `sha256/` prefixed, with at least one backup pin whose expiry is
beyond the primary's so a rotation cannot brick clients.

## 3. IOS PINNING TRUST SOURCES

```bash
# Static indicators of pinning/delegate hooks
strings App.app/App | grep -iE 'TrustKit|pinning|publicKey|SSLPinning|serverTrust'
nm -gU App.app/App 2>/dev/null | grep -iE 'TrustKit|SecTrust|anchor'
plutil -p App.app/Info.plist | grep -i 'NSAppTransportSecurity' -A5
```

Effective pinning on iOS requires `URLSession:didReceiveChallenge:` to use
`SecTrustEvaluateWithError` with custom anchors and must re-evaluate on every
challenge. A common failure: the delegate accepts the challenge on the *first*
call and caches trust, so a later redirect to an attacker host reuses the
positive result.

## 4. INTERCEPTION VALIDATION

For an authorized test, confirm your proxy certificate is accepted end to end:

1. Build/bring up your interception proxy with a CA installed on the test device.
2. Set the device proxy, launch the app, exercise each authenticated API call.
3. Record whether TLS handshakes fail, and whether failures are uniform across
   all hosts or only some.

Uniform failure across all hosts suggests strong pinning. Failure for only the
API host, while image/CDN hosts succeed, indicates partial or debug-build
pinning. A fully successful interception with a release-signed APK indicates the
control is absent or undermined in code.

Never install intercepting tooling on a device you do not own or have written authorization to test.

## 5. BYPASS SURFACE ASSESSMENT

Document which of these make the app interceptable under a stated threat model
(physical access, compromised device, malicious MDM, developer machine):

- A debuggable build, or a debug build type shipped to the store.
- A Java-level TLS hook (Frida/Xposed) reaching `javax.net.ssl.SSLContext` or
  OkHttp `CertificatePinner`, which trivially defeats all app-level pinning.
- An instrumentation hook on `SSLContext.init`, applied before pinning code
  executes.
- Native pinning (OpenSSL `SSL_CTX_set_verify` with a custom CA store), harder
  to hook but not impossible.
- Absence of runtime detection for injected libraries or debuggers.

## 6. FINDING QUALITY BAR AND RESPONSIBLE TESTING

Report the trust anchor actually loaded, the pin-set contents and expiration,
whether user CAs are trusted in release builds, and whether pinning covers every
domain in use, including redirects to third-party hosts. A pinning control that
omits one API subdomain is functionally absent.

Test only applications you own or have written authorization to assess, on a
device you control. Never install interception tooling, a CA, or a hooking
framework on another user's device, never intercept traffic from a third-party
service, and never retain real user credentials from intercepted sessions; keep
any captured data to a synthetic token you created. Prefer static analysis of your
own build artifact where dynamic validation would require touching someone else's
device.

## 7. RECOMMENDED HARDENING

Enforce pinning in native code where feasible, plus runtime integrity checks. Pin
multiple subjects with rotation lead time. Add release-build CI checks that fail
if `android:debuggable="true"` or a `user` CA trust anchor appears in a release
variant, and document the rotation runbook.

## Sources
- CWE-295: https://cwe.mitre.org/data/definitions/295.html
- OWASP MASTG: https://mas.owasp.org/MASTG/
- Android Network Security Configuration: https://developer.android.com/privacy-and-security/security-config
