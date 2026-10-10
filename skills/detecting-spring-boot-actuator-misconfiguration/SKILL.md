---
name: detecting-spring-boot-actuator-misconfiguration
description: >-
  Detect exposed Spring Boot Actuator endpoints that leak configuration, secrets, and administrative functions.
---

# SKILL: Detect exposed Spring Boot Actuator endpoints that leak configuration, secrets, and administrative functions.

> **AI LOAD INSTRUCTION**: Load when assessing Spring Boot services, reviewing actuator exposure settings, or triaging discovered actuator instances.

## 0. RELATED ROUTING
- [detecting-secrets-in-repositories](#) for credentials surfaced by `/env` or `/configprops`
- [unauthorized-access-common-services](#) for management ports left internet-reachable
- [api-recon-and-docs](#) for enumerating the full endpoint catalogue
- [detecting-graphql-schema-introspection-disabled-bypass](#) for the analogous hidden-surface problem

## 1. FINGERPRINT SPRING BOOT

```bash
curl -s -D- -o /dev/null https://target.tld/ | grep -iE 'x-application-context|whitelabel'
curl -s -o /dev/null -w 'actuator:%{http_code}\n' https://target.tld/actuator
curl -s -o /dev/null -w 'mgmt:%{http_code}\n' https://target.tld:8080/actuator
curl -s -o /dev/null -w 'health:%{http_code}\n' https://target.tld/actuator/health
curl -s -o /dev/null -w 'info:%{http_code}\n' https://target.tld/actuator/info
```

A `Whitelabel Error Page` body, `{"timestamp":...,"status":500}` JSON error shape, or an
`X-Application-Context` header identifies Spring Boot.

## 2. ENUMERATE THE DISCOVERY DOCUMENT

```bash
curl -s https://target.tld/actuator | jq -r '._links | keys[]'
```

Then check each individually — discovery output can list endpoints that are individually denied.

| Endpoint | Sensitivity |
|---|---|
| `/actuator/health` | Low if only `UP/DOWN`; high if it lists DB/Redis/Elastic URIs |
| `/actuator/info` | Build metadata, Git commit, sometimes internal hostnames |
| `/actuator/env` | **Critical** — environment variables, often including secrets |
| `/actuator/configprops` | **Critical** — bound properties incl. brute-forceable secrets |
| `/actuator/heapdump` | **Critical** — full JVM heap with in-memory credentials |
| `/actuator/threaddump` | High — internal state, connection metadata |
| `/actuator/mappings` | High — every controller route and method |
| `/actuator/loggers` | Medium — settable to DEBUG at runtime to leak request data |
| `/actuator/beans` | Medium — dependency graph |
| `/actuator/httptrace` / `/scheduledtasks` / `/caches` | Medium–High |

## 3. READ-ONLY VERIFICATION

All of these are GETs. Avoid `POST /loggers`, `DELETE /caches`, and any `POST /shutdown` or
`POST /refresh` — state-changing, and they need explicit authorization even on authorized systems.

```bash
curl -s -o /dev/null -w 'env:%{http_code}\n' https://target.tld/actuator/env
curl -s -o /dev/null -w 'props:%{http_code}\n' https://target.tld/actuator/configprops
curl -s -o /dev/null -w 'heap:%{http_code}\n' https://target.tld/actuator/heapdump
curl -s -o /dev/null -w 'mappings:%{http_code}\n' https://target.tld/actuator/mappings
curl -s https://target.tld/actuator/mappings 2>/dev/null | jq -r '.contexts[].mappings[].predicate' | head -30
```

`/actuator/mappings` is the highest-value read-only target: it enumerates the complete internal API
surface, including routes never linked from any UI and routes meant only for internal callers.

## 4. COMMON MISCONFIGURATIONS

```yaml
# application.yml — everything public, no auth
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    health:
      show-details: always
# application.properties: management.endpoints.web.exposure.include=*
```

Also check for: actuator on the app port instead of a management port; `management.server.port` bound to
`0.0.0.0` with no firewall; `management.context.base-path=/`; cloud security groups exposing the actuator
port; Spring Security present but no `SecurityFilterChain` covering the actuator path; exposure include
overridden at runtime by an env var.

```bash
grep -rn 'management.endpoints\|exposure\|actuator' application.yml application.properties 2>/dev/null | head -20
env | grep -iE 'MANAGEMENT_|SPRING_PROFILES' | head
```

## 5. RESPONSIBLE CONFIRMATION

A `200` on `/actuator/env`, `/configprops`, or `/heapdump` is already a confirmed critical finding needing
no further exploitation. Do not download a production heapdump — it contains live session tokens and PII,
and pulling it copies sensitive data outside its intended controls. On authorized systems, confirm
sensitivity by fetching a **single non-sensitive key** from `/actuator/env` and noting that others
exist, rather than dumping the document. If a heapdump is genuinely required, do it in an agreed window,
hash and encrypt it, and destroy it per the engagement data-handling terms.

## 6. REMEDIATION

Set `management.endpoints.web.exposure.include=health,info` and `health.show-details=when-authorized`.
Bind the management port to an internal interface (`management.server.address=127.0.0.1` or a private NIC)
with firewall and mTLS. Require Spring Security via a separate `SecurityFilterChain`. Disable `heapdump`
unless actively used. Add a CI check that fails when exposure includes anything beyond `health,info`, and
recurring external scanning for `/actuator` reachability.

## Sources
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-16: https://cwe.mitre.org/data/definitions/16.html
- Spring Boot Actuator Endpoints docs: https://docs.spring.io/spring-boot/reference/actuator/endpoints.html
- OWASP REST Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
