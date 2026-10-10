---
name: detecting-tomcat-ghostcat-ajp-file-inclusion
description: >-
  Detect GhostCat (CVE-2020-1938) AJP file inclusion and insecure AJP listener configuration in Tomcat.
---

# SKILL: Detect GhostCat (CVE-2020-1938) AJP file inclusion and insecure AJP listener configuration in Tomcat.

> **AI LOAD INSTRUCTION**: Load when assessing Tomcat deployments, auditing `server.xml` AJP connectors, or triaging AJP exposure.

## 0. RELATED ROUTING
- [path-traversal-lfi](#) for the file-inclusion primitive once AJP is reachable
- [detecting-nginx-off-by-slash-alias-misconfiguration](#) for the proxy-side parallel finding
- [detecting-apache-mod-proxy-path-normalization-bypass](#) for frontend/backend path disagreement
- [exploiting-http-request-smuggling](#) for related frontend/backend parsing disagreements

## 1. WHAT GHOSTCAT IS

Tomcat's AJP connector (port 8009 by default) speaks a binary protocol that the `ajp` valve and the
AJP request handler translate into internal servlet requests. The AJP handler honored an attacker-controlled
`javax.servlet.include.*` prefix, letting a request set the *response* to a local file path. That is
arbitrary local file read — and, when combined with a writable upload directory, file inclusion and RCE.

## 2. FINGERPRINT TOMCAT

```bash
curl -s -D- -o /dev/null http://target.tld:8080/ | grep -iE 'server:|x-powered-by'
curl -s http://target.tld:8080/ -o /dev/null -w '%{http_code}\n'
curl -s http://target.tld:8080/manager/html -o /dev/null -w 'manager:%{http_code}\n'
nc -zv -w3 target.tld 8009 2>&1 | tail -1
nc -zv -w3 target.tld 8443 2>&1 | tail -1
```

The AJP port being reachable from an untrusted network is the finding — it needs no payload to state.
A TCP connect succeeding and an `AJP` handshake (`0x12341234` magic) confirms the protocol responds.

## 3. CONFIGURATION REVIEW (DEFENSIVE, PRIMARY)

```bash
grep -n 'AJP' conf/server.xml
grep -n 'secretRequired\|address\|bindOnInit' conf/server.xml
grep -rn 'ALLOW_BACKSLASH\|allowLinking\|encodedSolidus' conf/web.xml
```

Vulnerable defaults to flag:

- `<Connector protocol="AJP/1.3" ...>` with no `secret` attribute
- No `address="127.0.0.1"` or `bindOnInit` restriction on the connector
- `secretRequired="false"` (Tomcat 9.0.31+ default in some distributions)
- `org.apache.catalina.valves.RemoteIpValve` absent while the connector sits behind an untrusted LB
- `<Valve className="org.apache.catalina.valves.AccessLogValve">` logging without the `%{X-Forwarded-For}i` safe pattern

## 4. READ-ONLY PROOF WITHOUT EXPLOITATION

The safest proof that the AJP handler honors `include` attributes is to request a file that exists on
every system and contains no secret — the Tomcat error page or a file you plant yourself in a temp dir
on a test instance.

```bash
# Harmless confirmation against a test system with a planted marker file
printf 'AJP-CONFIRMATION-MARKER\n' > /tmp/ajp_marker.txt   # on the TEST target only
```

Then submit an AJP forward request whose `javax.servlet.include.request_uri` points at that marker.
A response body containing `AJP-CONFIRMATION-MARKER` with status 200 proves file inclusion; anything
else (403, 400, connection reset) means the connector is patched or the marker path is not readable.

Do **not** aim the `include` at `/WEB-INF/web.xml`, `/etc/passwd`, or Tomcat `conf/server.xml` on a
production target. If your engagement requires proving sensitivity, request a path you have already
confirmed is outside the web root but inside a directory you control on a staging system, or supply a
marker file. Where a demonstration is unavoidable on an authorized system, use a plant-only file and
confirm cleanup in the report.

## 5. AJP TRAFFIC DETECTION

```bash
# Any AJP traffic at all in a captured session
tshark -r cap.pcap -Y 'tcp.port == 8009' -T fields -e ip.src -e ip.dst | sort -u | head
# Defensive Tomcat access log signature of AJP-origin requests
grep 'AJP/1.3' access.log.* | awk '{print $1}' | sort | uniq -c | sort -rn
```

Any AJP connection from an address other than the front-end proxy is anomalous by default.

## 6. HARDENING

Patch Tomcat past 9.0.31 / 8.5.51 / 7.0.88 (and later fixes). If AJP is unused, delete the connector
entirely — that is the strongest fix. If required, set `secret="..."` on both ends, restrict `address`
to the proxy interface, keep `secretRequired="true"`, and place Tomcat on a separate internal network.
Never expose 8009 through a cloud security group or an internet-facing load balancer. Add a startup
check that fails if an AJP connector lacks a secret or binds to a non-loopback address.

## Sources
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CVE-2020-1938 (GhostCat) — NVD: https://nvd.nist.gov/vuln/detail/CVE-2020-1938
- Apache Tomcat AJP documentation: https://tomcat.apache.org/tomcat-9.0-doc/config/ajp.html
- Qualys GhostCat disclosure: https://www.qualys.com/2020/09/30/apache-tomcat-vulnerability-ghostcat
