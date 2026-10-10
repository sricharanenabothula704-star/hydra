---
name: detecting-exposed-monitoring-dashboard-public-access
description: >-
  Grafana, Kibana, Prometheus, and similar telemetry consoles leak infrastructure topology, query history, and often credentials when reachable anonymously.
---

# SKILL: Grafana, Kibana, Prometheus, and similar telemetry consoles leak infrastructure topology, query history, and often credentials when reachable anonymously.

> **AI LOAD INSTRUCTION**: Load when assessing observability stacks for anonymous or internet-reachable dashboards during an authorized external review.

## 0. RELATED ROUTING
- [detecting-exposed-database-admin-panel-portal](#) for the sibling admin-console class
- [detecting-exposed-devops-tooling-ci-cd-endpoint](#) for build infrastructure in the same estate
- [detecting-directory-listing-exposure-sensitive-files](#) for dashboards discovered by index browsing

## 1. WHY OBSERVABILITY TOOLING LEAKS SO MUCH

Monitoring UIs are not designed as internet-facing software, but they are deployed
broadly and often left with authentication disabled during migration from a
self-hosted Prometheus. Grafana in particular permits anonymous access with an
`auth.anonymous.enabled` setting and per-organization viewer role, which looks like a
login wall that is actually a door. Kibana ships with a demo space and a sample
dashboard under `kibana demo` in old versions. Prometheus itself has no auth at all
and exposes every label value and metric name.

What leaks from an anonymous view: internal hostnames and IP ranges, service
topology, deployment timing, metric and label names (which reveal infrastructure
names in plaintext), query history showing internal URLs, and dashboards that embed
live API responses from backends.

## 2. PASSIVE FINGERPRINTING

Match on distinctive body strings and headers, not on status codes:

```
for p in /grafana/ /kibana/ /prometheus/ /alertmanager/ /thanos/ \
         /jaeger/ /zipkin/ /signalfx/ /datadog/ /newrelic/ /signoz/ /grafana/public/; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $p\n" "https://target.example$p"
done
curl -s https://target.example/grafana/health | head -c 200
curl -sI https://target.example/grafana/login | grep -iE 'server|set-cookie|location'
```

Markers: Grafana's `"version"` and `grafanaBootData`; Kibana's
`savedObjects:7:xpack` or the Elasticsearch `X-elastic-product` header;
Prometheus's `<title>Prometheus Time Series Collection and Processing Server</title>`;
Alertmanager's `/api/v2/status`.

## 3. THE UNAUTHENTICATED ENDPOINTS THAT PROVE IT

These answer without credentials and are safe to query read-only. A 200 is the
finding — no login is required to demonstrate it:

```
curl -s https://target.example:9090/api/v1/status/buildinfo | head -c 300
curl -s https://target.example:9090/api/v1/label/__name__/values | head -c 500
curl -s https://target.example:9090/api/v1/alerts | head -c 300
curl -s https://target.example/kibana/api/status | head -c 300
curl -s https://target.example:9093/api/v2/status | head -c 200   # Alertmanager
```

`/api/v1/label/__name__/values` is the highest-signal endpoint: it returns the
complete metric inventory as a flat JSON array, which maps the entire monitored
estate. On Grafana, `GET /api/health` and an unauthenticated `GET /api/dashboards/home`
distinguish "login required" from "anonymous viewer".

## 4. CONFIRMING ANONYMOUS VIEWERSHIP

Do not click through dashboards or read production data. A 200 on a dashboard API
endpoint, combined with a 401 on `/api/search`, is the precise signature of anonymous
viewer mode:

```
curl -s -o /dev/null -w 'dashboards:%{http_code}\n' https://target.example/grafana/api/dashboards/home
curl -s -o /dev/null -w 'search:%{http_code}\n'   https://target.example/grafana/api/search
curl -s -o /dev/null -w 'datasources:%{http_code}\n' https://target.example/grafana/api/datasources
```

A 200 on `/api/datasources` in particular can return database connection strings
including credentials, so treat its reachability as the evidence and do not read
the body into a report.

## 5. REMEDIATION VERIFICATION

- Disable anonymous access: `auth.anonymous.enabled = false` in Grafana; remove the
  Kibana demo space; put Prometheus behind an authenticating reverse proxy such as
  oauth2-proxy.
- Bind monitoring services to internal interfaces and enforce mTLS or SSO at the edge.
- Never expose raw Prometheus; front it with an auth proxy that applies per-tenant
  label filtering so tenants cannot read each other's metrics.
- Move credentials out of datasource URLs into a secret store with runtime injection.
- Scrub internal hostnames from externally visible dashboards.

## 6. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Confirm
*reachability and anonymity* with the status and label endpoints listed above, and
stop there. Do not open dashboards, do not query production metrics, do not enumerate
alert recipients, and do not read datasource credentials out of API responses.
Telemetry can contain customer identifiers and operational secrets; treat any metric
name, label, or alert payload as sensitive and report it by category rather than
verbatim. Coordinate timing with the owner so an audit of access logs can confirm
whether anonymous views already occurred.

## Sources
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- Grafana authentication docs: https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/anonymous-auth/
