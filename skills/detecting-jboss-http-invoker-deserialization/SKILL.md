---
name: detecting-jboss-http-invoker-deserialization
description: >-
  Detect JBoss HTTP Invoker and JMXInvoker endpoints that deserialize untrusted input.
---

# SKILL: Detect JBoss HTTP Invoker and JMXInvoker endpoints that deserialize untrusted input.

> **AI LOAD INSTRUCTION**: Load when fingerprinting JBoss/WildFly, reviewing EJB invoker config, or triaging deserialization alerts.

## 0. RELATED ROUTING
- [deserialization-insecure](#) for the underlying language-level defect
- [detecting-weblogic-deserialization-remote-code-execution](#) for the equivalent WebLogic T3 pattern
- [jndi-injection](#) for JNDI lookups chained after successful deserialization
- [unauthorized-access-common-services](#) for management interfaces left unauthenticated

## 1. FINGERPRINT JBOSS PASSIVELY

```console
$ curl -s -D- -o /dev/null http://target.tld:8080/ | grep -iE 'server:|x-powered-by|jboss'
$ curl -s -o /dev/null -w 'invoker:%{http_code}\n' http://target.tld:8080/invoker/JMXInvokerServlet
$ curl -s -o /dev/null -w 'ejb:%{http_code}\n' http://target.tld:8080/invoker/EJBInvokerServlet
$ curl -s -o /dev/null -w 'jmx:%{http_code}\n' http://target.tld:8080/jmx-console/
$ curl -s -o /dev/null -w 'web:%{http_code}\n' http://target.tld:8080/web-console/
$ curl -s -o /dev/null -w 'jolokia:%{http_code}\n' http://target.tld:8080/jolokia/
$ curl -s -o /dev/null -w 'mgmt:%{http_code}\n' http://target.tld:9990/management
```

A `200` on `/invoker/JMXInvokerServlet` or `/invoker/EJBInvokerServlet` from an unauthenticated
context is the headline finding. `Server: JBoss-*` or `X-Powered-By: JSP/2.3` plus the presence of
`jbossws` on the classpath confirm the platform.

## 2. INVOKER CONFIGURATION DEFECTS

The dangerous pattern is in `jboss-deployment-structure.xml` and `wildfly-config.xml`:

```xml
<!-- High risk: invoker binds to any-address with no security realm -->
<http-invoker security-realm="AppRealm" http-upgrade-enabled="true"
             listener="http-transport" path="/invoker/EJBInvokerServlet"/>
```

Red flags in `standalone.xml` / `domain.xml`:
- `<http-invoker>` without a `security-realm`
- `<security-realm>` where `<jaas>` is absent or `flag="required"` is missing
- Management interfaces bound to `public` interface with no `management-security-realm`
- JMX remote (`com.sun.management.jmxremote.port`) enabled without authentication
- `<protocol>` interfaces exposing the `jboss-mgmt` and `jmx` management services on `0.0.0.0`

On WildFly, verify:

```console
$ ./jboss-cli.sh --connect --commands='/core-service=management:read-resource'
$ ./jboss-cli.sh --connect --commands='/subsystem=undertow:read-resource'
```

## 3. READ-ONLY DESERIALIZATION PROOF

Use a serialized `String` object only. `java.lang.String` is not a gadget class and cannot trigger a
chain, but its presence in the stream proves the servlet is reading objects off the wire.

```bash
# Harmless: stream header + a String payload. No gadget classes present.
printf '\xac\xed\x00\x05\x74\x00\x08probe\x41\x00\x05probe' > /tmp/str.ser
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/x-java-serialized-object' \
  --data-binary @/tmp/str.ser http://target.tld:8080/invoker/EJBInvokerServlet
```

Interpretation:

| Response | Meaning |
|---|---|
| `400` with a serialization error message | Sink reachable, untrusted input reaches `readObject` |
| `401`/`403` | Auth enforced before deserialization — good |
| `500` with `ClassNotFoundException` | Deserialization proceeds; class loading is the next gate |
| `200` | Full read plus method dispatch — critical |

Any of the first three is already a reportable finding requiring the security realm fix; only the last
demonstrates exploitability, and confirming that requires explicit authorization.

## 4. EXPOSURE AND CONTAINMENT CHECKS

```bash
# Management interfaces must not be internet-reachable
for p in 9990 9993 1099 3873 4445 4713 8083; do nc -zv -w2 target.tld $p; done
# JMX remote with no auth
nc -zv target.tld 1099 && echo 'jmx-rmi exposed'
# Jolokia over HTTP is unauthenticated by default in older versions
curl -s http://target.tld:8080/jolokia/list | jq '.value | keys' | head
```

## 5. RESPONSIBLE CONFIRMATION

Fingerprinting and the serialized-`String` probe are safe against production. Gadget-chain payloads —
which can instantiate `CommonsCollections` transformers, `Jdk7u21` gadgets, or `BeanUtils` chains — must
only be sent to systems with explicit written authorization and a documented test window. When proof of
code execution is required on such systems, prefer an OOB callback object (DNS or HTTP egress to a
collaborator domain) over any payload that opens a shell, writes a file, or creates a new account.

## 6. HARDENING

Upgrade past the affected advisories. Remove `<http-invoker>` unless legacy EJB-over-HTTP is genuinely
required; prefer remote EJB over the remoting connector with proper TLS. Bind management interfaces to
an internal interface only and place them behind a management firewall. Require `security-realm` with
JAAS on every invoker. Enable Java serialization filters (`jdk.serialFilter`) allowlisting only the
types your application legitimately uses. Disable Jolokia or put it behind authentication and a
management-only network. Alert on any external access to 9990/1099/3873.

## Sources
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- JBoss/WildFly Documentation: https://docs.wildfly.org/
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
