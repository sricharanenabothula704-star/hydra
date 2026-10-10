---
name: detecting-weblogic-deserialization-remote-code-execution
description: >-
  Detect unsafe Java deserialization and T3/IIOP exposure in Oracle WebLogic Server.
---

# SKILL: Detect unsafe Java deserialization and T3/IIOP exposure in Oracle WebLogic Server.

> **AI LOAD INSTRUCTION**: Load when fingerprinting WebLogic, reviewing `wl-app` endpoints, or triaging Java deserialization alerts.

## 0. RELATED ROUTING
- [deserialization-insecure](#) for the language-level deserialization defect classes
- [jndi-injection](#) for the Log4Shell/JNDI lookup chain commonly chained after RCE
- [hunting-for-unusual-network-inbound-connections](#) for exposing T3/IIOP listeners from NetFlow
- [performing-jndi-lookup-classloader-abuse](#) for ClassLoader-based gadget-chain confirmation

## 1. FINGERPRINT WEBLOGIC PASSIVELY

```console
$ curl -s -D- -o /dev/null https://target.tld:7002/ 2>/dev/null | grep -iE 'server:|x-oracle|www-authenticate'
$ curl -s -o /dev/null -w '%{http_code}\n' https://target.tld:7001/wl-management/
$ curl -s -o /dev/null -w '%{http_code}\n' https://target.tld:7001/console/
$ curl -s -o /dev/null -w '%{http_code}\n' http://target.tld:7001/
$ curl -s -o /dev/null -w '%{http_code}\n' http://target.tld:7001/wl-app/server/api
$ curl -s -o /dev/null -w '%{http_code}\n' http://target.tld:7001/wlr
```

Ports to probe: 7001 (HTTP), 7002 (HTTPS), 7003, 8001 (admin), and 7101/7102 (RMI/t3 alternate).
`Server: WebLogic Server` in the response header or a `WWW-Authenticate: Basic realm="Oracle WebLogic Server"`
confirms the platform and its exact build from the console version banner.

## 2. T3/IIOP AND RMI LISTENER POSTURE

The high-value question is whether the binary RMI ports are reachable from untrusted networks.

```console
$ nc -zv target.tld 7001; nc -zv target.tld 7002; nc -zv target.tld 7101; nc -zv target.tld 7102
$ openssl s_client -connect target.tld:7002 -quiet <<< 'AAAB' 2>/dev/null | head -c 200 | xxd | head
```

A successful handshake followed by an `IIOP` or `ACED0005` magic byte confirms the RMI/T3 protocol is
live. `ACED0005` is the Java serialization stream header — its presence on a port reachable from the
internet is the core finding, independent of any gadget chain.

Classify the finding on reachability alone:

| Exposure | Severity |
|---|---|
| Port bound to `0.0.0.0` and reachable from internet | Critical |
| Reachable from internal network only, no auth | High |
| Bound to management interface, ACL-restricted | Medium |
| Loopback or host-firewalled | Informational |

## 3. DESERIALIZATION SINKS IN WEBLOGIC

WebLogic deserializes in several places: the T3 protocol handler, JMS queues, `com.bea.core` weblogic
work units, and any deployed EAR/EJB/WAR that consumes serialized objects from HTTP, LDAP, or a
file share. Identify the app-layer sinks separately:

```console
$ grep -rniE 'ObjectInputStream|readObject|readUnshared|XMLDecoder|XStream.fromXML' --include=*.java . | head -30
$ grep -rniE 'readObject|ObjectInputStream' WEB-INF/classes 2>/dev/null | head
$ find . -name '*.war' -o -name '*.ear' | xargs -I{} sh -c 'unzip -l {} | grep -cE "commons-collections|commons-beanutils|groovy|rhino" ' 2>/dev/null | head
```

Third-party libraries bundled into EAR/WAR archives (Commons Collections 3.x, Groovy, Rhino, C3P0,
ROME, JRMPClient) determine gadget availability without any patching.

## 4. READ-ONLY CONFIRMATION APPROACH

Do not send crafted gadget chains to production WebLogic. Confirm instead with:

1. Protocol identification: the `ACED0005`/`IIOP` handshake described above.
2. Version identification: the console version banner and `/console/login/LoginForm.js` asset.
3. Patch state: compare against the current CPU advisory for the exact version.
4. Network controls: verify source-IP ACLs on the RMI port from a scanner positioned *outside* the
   intended trust zone.

If a client-side deserialization endpoint exists in a webapp (for example, a JMS-over-HTTP bridge or a
coercion-friendly endpoint), prove it with a **read-only** probe: send a serialized `String` and confirm
the application processes it. String serialization cannot instantiate gadget classes and cannot execute
code — it only proves the sink is reachable. That is the appropriate boundary for a non-destructive
engagement.

For fully authorized engagements requiring code-execution proof, prefer **OOB**: supply a serialized
object that performs only a DNS or HTTP lookup to a collaborator endpoint. This confirms the gadget
chain executes while producing no shell, no file write, and no persistence on the target.

## 5. HARDENING

Apply the latest Oracle CPU for WebLogic. Set `-Dweblogic.maxReceiveBufferSize` low and disable T3/IIOP
where unused (`-Dweblogic.r3.disabled=true` is not a complete fix — restrict the channel instead).
Bind admin and RMI listeners to a dedicated management NIC, restrict with ` weblogic.channels.internal`
plus host firewall ACLs. Enable Java serialization filters (`jdk.serialFilter`) with an allowlist
rather than rely on a denylist of known gadget classes. Enforce HTTPS with mutual TLS on the admin
channel and place the console behind SSO. Add a network alert on any new external connection to
7001/7002/7101/7102.

## Sources
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- CWE-918: https://cwe.mitre.org/data/definitions/918.html
- Oracle Critical Patch Updates: https://www.oracle.com/security-alerts/
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
