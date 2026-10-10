---
name: detecting-ios-webview-javascript-bridge-exposure
description: >-
  Detect exposed WKWebView message handlers, JS bridges, and unsafe URL loading in iOS applications.
---

# SKILL: Detect exposed WKWebView message handlers, JS bridges, and unsafe URL loading in iOS applications.

> **AI LOAD INSTRUCTION**: Load when reviewing an iOS app's WebView configuration, message handlers, and navigation policy.

## 0. RELATED ROUTING
- [analyzing-ios-app-security-with-objection](#) for runtime hooks and SSL pinning bypass
- [reverse-engineering-ios-app-with-frida](#) for dynamic instrumentation
- [detecting-android-intent-redirect-component-abuse](#) for the Android equivalent surface

## 1. THE IOS WEBVIEW RISK MODEL

`WKWebView` grants page JavaScript a direct channel into native code. Risks:

- `WKScriptMessageHandler` registered with a loose name and no origin check
- `WKUserContentController.addUserScript` injecting bridges into *all* origins
- `evaluateJavaScript` executing strings built from navigation state or query parameters
- `loadFileRequest` allowing `file://` reads on older iOS
- Navigation delegate `decidePolicyFor` that allows `http://` or any unknown host

## 2. STATIC REVIEW

Extract the app and inspect the binary for bridge names and handler selectors:

```
otool -L Payload/App.app/App
strings -a Payload/App.app/App | grep -nEi 'userContentController|scriptMessageHandler|addUserScript|evaluateJavaScript|postMessage|webkit\.messageHandlers|shouldStartLoadWithRequest|decidePolicyFor'
```

In Swift/ObjC sources, look for handler registration without a per-host check:
```
grep -rnE 'add\(self, name:|addScriptMessageHandler|WKUserScript\(source|evaluateJavaScript\(' App/
grep -rnE 'decidePolicyFor.*navigationAction|loadFileRequest|allowingReadAccessTo' App/
```

## 3. RUNTIME INSPECTION (YOUR OWN DEVICE / DEBUG BUILD)

Inspect registered message handlers with Frida against your own debug build:

```
frida -U -f com.example.app -l dump-handlers.js
```

Drive the WebView to your own test host page and enumerate handler names:

```javascript
// test-host page served from a host you control
Object.keys(window.webkit.messageHandlers)
```

Any handler not narrowly named and origin-scoped is a candidate exposure.

## 4. PROBE HANDLER INVOCATION

From your own controlled page, invoke the bridge with benign payloads:

```javascript
window.webkit.messageHandlers.postMessage({ action: "getProfile" });
window.webkit.messageHandlers.postMessage({ action: "openURL", url: "https://example.com" });
window.webkit.messageHandlers.postMessage({ action: "eval", src: "1+1" });
```

Test whether the handler validates the action, rejects unknown actions safely, and whether it
can be driven from a third-party origin loaded in the same WebView. Use a host you run yourself
on your own device only.

## 5. NAVIGATION POLICY AND LOAD

Verify the app restricts which URLs may load:

- `http://` loads blocked or upgraded; `file:`, `data:`, `javascript:` rejected in navigation.
- Universal link routing maps only your own domains into the WebView.
- `decidePolicyFor navigationAction` validates host, not just scheme.

Test with your own alternate host redirecting to a page you control that then calls the bridge.

## 6. DEEPLINK -> WEBVIEW CHAIN

Universal Links and custom schemes both eventually reach native code. Trace whether a parameter controls
the URL loaded into the WebView (an open redirect into a privileged bridge).

```
xcrun simctl openurl booted "https://your-host.example/redirect?to=your-test-host"
```

Confirm whether the `to` value is validated against an allowlist before loading.

## 7. FIX RECOMMENDATIONS

1. Register one narrowly named `WKScriptMessageHandler`; reject unexpected action names.
2. Add a per-message origin check; never trust the message payload as the authority.
3. Scope `WKUserScript` injection to the specific origin and a targeted content world.
4. In `decidePolicyFor`, allowlist hosts and schemes; block `http`, `file`, `data`, `javascript`.
5. Avoid `evaluateJavaScript` with string interpolation from navigation or query input.
6. Disable WebView debugging (`isInspectable`) in release builds.
7. Isolate third-party SDK WebViews from privileged bridges entirely.

## 8. RESPONSIBLE TESTING

Only test apps you own or have written authorization to assess, on your own device, emulator, or
simulator, driving pages and hosts you control. Never target another app's WebView or a live third-party
origin to invoke a bridge, and never use a discovered bridge to reach data outside your own
account; report instead of exploiting.

## Sources
- CWE-749: https://cwe.mitre.org/data/definitions/749.html
- CWE-940: https://cwe.mitre.org/data/definitions/940.html
- OWASP MASTG iOS Webview: https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0032/
- Apple WKWebView docs: https://developer.apple.com/documentation/webkit/wkwebview
