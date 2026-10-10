---
name: detecting-android-intent-redirect-component-abuse
description: >-
  Detect exported components, intent redirection, and task hijacking in Android applications.
---

# SKILL: Detect exported components, intent redirection, and task hijacking in Android applications.

> **AI LOAD INSTRUCTION**: Load when assessing an Android app manifest for exported activities, services, receivers, and providers.

## 0. RELATED ROUTING
- [analyzing-android-malware-with-apktool](#) for manifest and resource analysis
- [testing-android-intents-for-vulnerabilities](#) for interactive IPC testing
- [performing-dynamic-analysis-of-android-app](#) for runtime component exercise

## 1. ATTACK SURFACE

Every Android component reachable from another app is an input. The manifest declares intent
filters, and Android auto-exports components with filters (pre-Android 12 defaults, and
`android:exported` is mandatory from API 31). Abuses to test:

- **Intent redirection** - an exported activity forwarding extras to an internal component
- **Start-anywhere** - a launcher/deeplink path that starts arbitrary exported targets
- **PendingIntent abuse** - a `PendingIntent` handed to another app, redirecting or mutating it
- **Content provider traversal** - `content://` URI with `..`, path traversal, or SQL injection
- **Broadcast injection** - unprotected or dynamically registered receivers
- **Task hijacking / StrandHogg** - `launchMode` plus an intent that resumes a disguised task

## 2. MANIFEST REVIEW

```
aapt dump xmltree app.apk AndroidManifest.xml | grep -E 'activity|service|receiver|provider|exported|permission|scheme|host'
apktool d app.apk -o apk_out && grep -nE 'exported|intent-filter|<data|grantUriPermissions' apk_out/AndroidManifest.xml
```

Flag: `exported="true"` without a permission; components with an intent filter and no explicit
`android:exported`; deep-link `<data android:scheme="http">` on sensitive screens; providers with
`grantUriPermissions="true"` and `android:readPermission` unset.

## 3. PROBE EXPORTED COMPONENTS

Launch components directly against your own build or an authorized app on your own device:

```
adb shell am start -n com.example.app/.ui.ExportedActivity --es token "test"
adb shell am start -a android.intent.action.VIEW -d "exp://test/../../internal" com.example.app
adb shell am start -a android.intent.action.VIEW -d "https://app.example.com/callback?next=file:///sdcard"
adb shell am broadcast -a com.example.app.ACTION_DEBUG --ez unlock true
adb shell content query --uri content://com.example.app.provider/items/../prefs
```

Observe with an emulator you control and `adb logcat`. Verify whether the component honors a
parameter that selects a privileged internal action.

## 4. INTENT REDIRECTION

If an exported activity builds a new intent from a parceled extra and starts it, test whether
the extra's component can be replaced.

```
adb shell am start -n com.example.app/.ui.ShareActivity \
  --es target_pkg com.other.app --es target_cls .PrivateActivity --es cmd "act=EXPORT"
```

Also test `PendingIntent` returned to a caller, and `Intent.parseUri()`/`Intent(String)` use,
which can rehydrate arbitrary intents from a string. Confirm the app validates `getComponent()`
against an allowlist.

## 5. CONTENT PROVIDER TESTING

```
adb shell content read --uri content://com.example.app.provider/table/1
adb shell content query --uri "content://com.example.app.provider/table?where=1=1--"
adb shell content read --uri content://com.example.app.provider/../../databases/app.db
```

With `app`'s debuggable build only (your own build), inspect what is actually returned. Look for
unprotected preferences, sessions, or cached tokens exposed through a provider.

## 6. DEEPLINK VALIDATION

Check whether deep links validate state and origin before performing actions:

```
adb shell am start -a android.intent.action.VIEW -d "exp://app/settings"
adb shell am start -a android.intent.action.VIEW -d "exp://app/admin?token=anything"
```

A deep link that performs a state-changing action without authentication is a finding.

## 7. FIX RECOMMENDATIONS

1. Set `android:exported="false"` unless a component genuinely needs external invocation.
2. Protect exported components with signature-level permissions and validate every intent extra.
3. Never build an outbound intent from untrusted strings; allowlist target components explicitly.
4. Use immutable `PendingIntent` (`FLAG_IMMUTABLE`) and set an explicit creator package.
5. Add `android:readPermission`/`writePermission` on providers; avoid exporting them.
6. Validate deep-link state, nonce, and session before executing privileged actions.

## 8. RESPONSIBLE TESTING

Test only apps you own or have explicit written authorization to assess, using your own device,
emulator, or test build. Probe components with benign placeholder data, never use values intended
to reach another user's data, and stop at confirming whether the guard is present. Report
findings rather than chaining them into exploitation.

## Sources
- CWE-926: https://cwe.mitre.org/data/definitions/926.html
- CWE-939: https://cwe.mitre.org/data/definitions/939.html
- OWASP MASTG Android: https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0033/
- Android intent security: https://developer.android.com/privacy-and-security/risks/intent-filter
