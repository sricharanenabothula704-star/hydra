---
name: detecting-ssti-in-vue-angular-client-templates
description: >-
  Client-side template injection in Vue/Angular (CSTI) and server-side rendering template injection. Covers Angular's bypassSanitization, Vue template compilation sinks, and SSR SSTI.
---

# SKILL: Client-side template injection in Vue/Angular (CSTI) and server-side rendering template injection. Covers Angular's bypassSanitization, Vue template compilation sinks, and SSR SSTI.

> **AI LOAD INSTRUCTION**: Load when a Vue/Angular SPA compiles user input as a template (client-side template injection) or an SSR engine renders user input. Covers Angular sanitization bypass, Vue runtime template compilation, and how these escalate to XSS.

## 0. RELATED ROUTING
- [exploiting-ssti-in-template-engines](#) for server-side SSTI
- [exploiting-cwe-79-cross-site-scripting-reflection-sinks](#) for the XSS class
- [detecting-csp-bypass-advanced](#) for post-XSS impact

## 1. ANGULAR: THE SANITIZATION TRAP

Angular's DomSanitizer `bypassSecurityTrustHtml/Url/Script` marks a string as trusted, disabling sanitization. If user input reaches a bypass* call, it's XSS. Also `innerHTML` binding (equivalent to bypass). Detect: `bypassSecurityTrust`, `[innerHTML]`, `eval()`.

## 2. VUE: RUNTIME TEMPLATE COMPILATION

Vue's `new Vue({template: userInput})` or `vue-template-compiler` on user data compiles user input as a template -> expression injection ({{ }} and directives). Detect `template:` bound to dynamic data, `$compile`, or a CDN-loaded vue.js full build (runtime+compiler) rendering dynamic templates.

## 3. SSR SSTI

Server-side rendering (Nuxt, Angular Universal, Next.js misuse) may compile the same user input server-side -> server RCE if the engine evaluates expressions. Same detection idea as SSTI but the sink is the SSR template.

## 4. SAFE CONFIRMATION

Prove template compilation with a harmless expression ({{1+1}} -> 2 for Vue; a benign DOM change for Angular) rather than executing script. Escalate to payload only with authorization.

## 5. REMEDIATION

Never compile user input as a template. Use data binding, not string templates. Keep Angular's default sanitization (no bypass*). Use Vue's runtime-only build; never pass user data to `template:`. CSP as defense-in-depth.

## Sources
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- CWE-1336: https://cwe.mitre.org/data/definitions/1336.html
- Angular security guide: https://angular.dev/best-practices/security

## 5. WHAT ACTUALLY EXECUTES

- Vue: `{{ constructor.constructor('alert(1)')() }}` reaches the Function constructor from template scope.
- Angular: reaching `constructor` from a component needs an extra hop through `window`, since templates compile in a restricted context.
- Both prove the sink evaluates expressions rather than treating input as inert data.

## 6. SUPPLY-CHAIN ANGLE

Vue's full build (`vue.js` with compiler) is the risk. If a project ships the runtime+compiler build and binds any user-derived string to `template:` or calls `Vue.compile()`, every one of those is a CSTI sink. Flag the full build plus dynamic templates together.

## 7. CONFIRMATION DISCIPLINE

Confirm template evaluation with a non-executing probe:

- Vue `{{7*7}}` renders `49` (proves evaluation, runs nothing)
- Angular a binding that sets a static attribute on a node you control

Escalate to a script payload only with written authorization. On bug bounty, "user input is compiled as a template and evaluates expressions" is a complete finding on its own — the expression evaluation IS the vulnerability.
