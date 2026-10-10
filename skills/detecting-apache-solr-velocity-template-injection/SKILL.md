---
name: detecting-apache-solr-velocity-template-injection
description: >-
  Detect Apache Solr Velocity template injection through untrusted query parameters and data directories.
---

# SKILL: Detect Apache Solr Velocity template injection through untrusted query parameters and data directories.

> **AI LOAD INSTRUCTION**: Load when assessing Solr instances, auditing `params.resource.loader.enabled`, or triaging SSRF via Solr.

## 0. RELATED ROUTING
- [ssti-server-side-template-injection](#) for the core template-injection analysis
- [ssrf-server-side-request-forgery](#) for the `resourceLoader`/`file://` SSRF chain
- [detecting-wordpress-rest-api-authorization-bypass](#) for the same param-echo class in another stack
- [performing-web-application-logging-with-modsecurity](#) for WAF rules on Solr query strings

## 1. FINGERPRINT SOLR

```bash
curl -s -D- -o /dev/null http://target.tld:8983/solr/ | grep -iE 'server:|x-solr'
curl -s http://target.tld:8983/solr/admin/info/system | jq '.lucene' 2>/dev/null
curl -s http://target.tld:8983/solr/admin/cores?action=STATUS | jq '.status' 2>/dev/null
curl -s -o /dev/null -w 'solr:%{http_code}\n' 'http://target.tld:8983/solr/'
curl -s -o /dev/null -w 'zk:%{http_code}\n' 'http://target.tld:8983/solr/admin/zookeeper'
```

`/solr/admin/info/system` and `/solr/admin/cores` are unauthenticated by default and disclose the
version, Java version, core list, and instance directory. Enumerate documents read-only:

```bash
curl -s 'http://target.tld:8983/solr/select?q=*:*&rows=0&wt=json' | jq '.response.numFound'
curl -s 'http://target.tld:8983/solr/admin/luke?numTerms=0' | jq 'keys' | head
```

## 2. THE VELOCITY VULNERABILITY CLASS

Solr's `VelocityResponseWriter` and the `/solr/<core>/admin/file` handler were the two vectors. The
`params` resource loader setting is the root control:

```xml
<!-- dangerous -->
<str name="params.resource.loader.enabled">true</str>
<!-- safe -->
<str name="params.resource.loader.enabled">false</str>
```

Reachability is what matters, and it is testable without exploiting anything:

```bash
# Does the core accept the params resource loader? Compare param echo behaviour.
curl -s -o /dev/null -w 'qt:%{http_code}\n' -G \
  --data-urlencode 'qt=$version' --data-urlencode 'wt=json' \
  'http://target.tld:8983/solr/select'
curl -s -o /dev/null -w 'tr:%{http_code}\n' -G \
  --data-urlencode 'tr=custom-handler' \
  'http://target.tld:8983/solr/select'
```

A `200` where an invalid value should be rejected shows the config accepts request-driven template
parameters. `qt` and `tr` in particular influence which handler and template are used.

ConfigDirectory exploitation (arbitrary file read/SSRF via `shards`/`replicationHandler`):

```bash
curl -s 'http://target.tld:8983/solr/core1/config?wt=json' -o /dev/null -w '%{http_code}\n'
curl -s 'http://target.tld:8983/solr/core1/admin/file?file=solrconfig.xml&wt=json' | head -c 300
```

Reading `solrconfig.xml` through the admin API is a **read-only** proof of directory traversal and
config disclosure that executes no attacker code. Start here before anything more invasive.

## 3. THE CORE-ADDITION RCE CHAIN

The most severe chain: create/reconfigure a core with `dataDir` pointing at a filesystem path, write a
Velocity template via `/admin/file`, then query. Detect the precondition read-only:

```bash
curl -s -o /dev/null -w 'create-core:%{http_code}\n' -H 'Content-Type: application/json' \
  'http://target.tld:8983/solr/admin/cores?action=CREATE&name=probe&configSet=_default'
curl -s 'http://target.tld:8983/solr/admin/cores?action=LIST&wt=json' | jq '.status[].name'
```

The precondition — *can an unauthenticated caller invoke the cores admin API at all* — is itself the
finding and needs no payload. If `CREATE` returns 200, confirm with `LIST` (read-only) that the core
exists, then `UNLOAD`/`DELETE` it to restore state. Creating a core is a write action: explicit
authorization only.

## 4. RESPONSIBLE CONFIRMATION PATH

Order of escalation, stopping as early as the finding is proven:

1. Passive: version, cores, `/admin/info/system`, `/admin/cores?action=STATUS`.
2. Read-only: read `solrconfig.xml` via `/admin/file`, inspect `params.resource.loader.enabled`.
3. Parameter acceptance: benign `qt`/`tr`/`rows` variations, checking status and behavior change.
4. Only with explicit written authorization: template evaluation with an **OOB DNS/HTTP callback** in
   place of any shell or file write. Never a reverse shell, never a payload that modifies `solr.xml`.

Solr often runs as a service account with broad filesystem access — treat "unauthenticated admin API
reachable" as RCE-equivalent and escalate the finding even without an execution proof.

## 5. HARDENING

Upgrade to a current Solr release. Enable authentication (SolrJ `jaas` or `BasicAuthPlugin`) on every
core and the admin API. Set `params.resource.loader.enabled=false`. Disable the `VelocityResponseWriter`
or restrict `solr.solrhome` permissions so templates cannot be written via `/admin/file`. Bind Solr to
an internal interface behind a proxy that strips `/solr/admin/*`. Run as an unprivileged user. Filter
`dataDir`, `configSet`, and `wt` at the proxy. Alert on `action=CREATE|UNLOAD|RELOAD`.

## Sources
- CWE-1336: https://cwe.mitre.org/data/definitions/1336.html
- CWE-917: https://cwe.mitre.org/data/definitions/917.html
- CVE-2017-12629 (Solr RCE) — NVD: https://nvd.nist.gov/vuln/detail/CVE-2017-12629
- OWASP Velocity SSTI research: https://owasp.org/www-community/attacks/SSTI
