---
name: detecting-struts2-ognl-classloader-access
description: >-
  Detect Apache Struts OGNL injection paths, especially `%{...}` ClassLoader access through parameters.
---

# SKILL: Detect Apache Struts OGNL injection paths, especially `%{...}` ClassLoader access through parameters.

> **AI LOAD INSTRUCTION**: Load when fingerprinting Struts 2 apps, reviewing OGNL-reachable actions, or triaging S2-xxx advisories.

## 0. RELATED ROUTING
- [ssti-server-side-template-injection](#) for the shared evaluation-primitive reasoning
- [expression-language-injection](#) for OGNL/SpEL/MVEL family mechanics
- [cmdi-command-injection](#) for the downstream sink once expression evaluation succeeds
- [hunting-for-lolbins-execution-in-endpoint-logs](#) for detecting post-exploitation tooling

## 1. FINGERPRINT STRUTS WITHOUT BEING OBVIOUS

```bash
curl -s -D- -o /dev/null https://target.tld/ | grep -iE '^server:|x-struts|x-powered-by|set-cookie.*JSESSIONID'
curl -s https://target.tld/index.action -o /dev/null -w 'index.action:%{http_code}\n'
curl -s https://target.tld/login.action -D- -o /dev/null | grep -i 'x-powered-by\|server'
```

Struts exposes characteristic error text (`There has been an error processing your request`,
`OgnlException`, `com.opensymphony.xwork2`) on malformed parameter names. This is a passive check that
does not evaluate anything meaningful:

```bash
curl -s 'https://target.tld/check' -G --data-urlencode 'x[1]=y' -o /dev/null -w '%{http_code}\n'
curl -s 'https://target.tld/?debug=1' | grep -ci 'struts'
```

Do **not** enumerate `/WEB-INF/web.xml` or `struts.xml` remotely; derive config from deployment knowledge
and package manifests instead.

## 2. THE CLASSLOADER ACCESS VECTOR

Several Struts 2 double-evaluation bugs (the `%{(...)%}` parameter-name family, and
`action:`/`redirect:` prefix handling) allowed reaching `java.lang.ClassLoader`. The relevant security
question is not "can I eval" but "does untrusted input reach any OGNL sink at all".

Detect the sink passively by looking for structural signals of the double-eval path:

```bash
# Parameter names that are themselves expressions. Harmless: returns 400/500, no eval of useful payload.
curl -s -o /dev/null -w '%{http_code}\n' -G --data-urlencode '%{#a="x"}' https://target.tld/x
curl -s -o /dev/null -w '%{http_code}\n' -G --data-urlencode 'x[#_=y]' https://target.tld/x
# Action prefix injection surface (probe only)
curl -s -o /dev/null -w '%{http_code}\n' 'https://target.tld/x?redirect:%24%7Ba%7D=%24%7Ba%7D'
```

Comparing the response for `%{#a="x"}` against `x(#a=x)` reveals whether the OGNL parser is on the
path: different status or error text means the parameter name is being parsed, which is the defect.

## 3. VULNERABLE CONFIG MARKERS

Struts versions are the primary control. Cross-check the deployment:

```bash
grep -rn 'struts2-core' pom.xml build.gradle */pom.xml 2>/dev/null | head
grep -rniE 'struts|ognl' WEB-INF/web.xml WEB-INF/classes/struts.xml 2>/dev/null | head -20
cat WEB-INF/classes/struts.properties 2>/dev/null | grep -iE 'devMode|struts.enable|ognl'
```

`struts.devMode=true` on a production deployment is itself a finding: it enables detailed OGNL stack
traces that hand an attacker the exact object graph they need.

Key patterns to flag in `struts.xml` and result types:
- `<result type="redirect">` with a `${...}` value taken from a request parameter
- ValueStack members bound from unvalidated request data used in `<s:property>` / `%{}`
- Custom interceptors that read `getParameterMap()` into the ValueStack
- `alwaysSelectFullNamespace` and Dynamic Method Invocation left enabled

## 4. THE PRECISE READ-ONLY PROBE

When a Struts deployment has been actively scanned, the safest confirmation is a **timing-free,
side-effect-free structural probe**:

```bash
# Compare a normal unknown param vs an OGNL-looking one. Same status + same body hash = no sink.
for p in 'foo' '%{1+1}' '${{1+1}}'; do
  h=$(curl -s -G --data-urlencode "x=$p" https://target.tld/x | sha256sum | cut -c1-16)
  printf '%-12s %s\n' "$p" "$h"
done
```

Identical hashes across all three mean the input is not evaluated. Differing hashes point at a sink and
warrant escalation to a controlled, authorized environment.

If an out-of-band confirmation is needed and the system is explicitly authorized, request a **DNS-only
callback** to a hostname you control via OGNL namespace access. DNS exfil proves evaluation without
writing files, spawning shells, or modifying application state — and it leaves a durable audit record
on your own infrastructure.

## 5. HARDENING

Upgrade to a Struts version not affected by the relevant S2 advisories. Disable DMI and devMode. Never
place user input into ValueStack roots or result expressions. Add a WAF rule matching `%{`, `${`, `(#`,
`@java.lang` in parameter names, keys, and referer. Enable `struts.mapper.action.prefix.enabled=false`
so `action:`/`redirect:` are treated as literal values. Run Struts with the lowest-privilege DB user and
a read-only filesystem for template directories so that even a successful injection cannot write.

## Sources
- CWE-917: https://cwe.mitre.org/data/definitions/917.html
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- Apache Struts Security Bulletins: https://struts.apache.org/security/
- OWASP Expression Language Injection: https://owasp.org/www-project-web-security-testing-guide/
