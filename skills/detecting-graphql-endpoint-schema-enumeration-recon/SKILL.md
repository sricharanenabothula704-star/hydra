---
name: detecting-graphql-endpoint-schema-enumeration-recon
description: >-
  GraphQL introspection returns the entire type system, queries, mutations, and internal directives in one unauthenticated request, collapsing endpoint discovery.
---

# SKILL: GraphQL introspection returns the entire type system, queries, mutations, and internal directives in one unauthenticated request, collapsing endpoint discovery.

> **AI LOAD INSTRUCTION**: Load when assessing GraphQL APIs for enabled introspection during an authorized external assessment or schema exposure review.

## 0. RELATED ROUTING
- [detecting-graphql-schema-introspection-disabled-bypass](#) for the attempts that defeat introspection blocking
- [detecting-api-documentation-swagger-endpoint-exposure](#) for the REST specification equivalent
- [detecting-idor-sequential-identifier-enumeration](#) for object-level access testing that follows

## 1. WHY INTROSPECTION IS STRUCTURALLY WORSE

REST hides its surface by default; GraphQL publishes a queryable type system. One
introspection query returns every object type, field name and type, enum values,
interfaces, unions, input types, deprecation reasons, and the full query/mutation/
subscription root. Because field names frequently embed business concepts — `salary`,
`internalRiskScore`, `billingAddress`, `resetToken`, `isAdminOverride` — a single
response documents internal data model details that no REST equivalent would leak.
Depth is also a usable proxy for complexity: the number of resolved fields correlates
with authorization surface.

## 2. THE MINIMAL PROBE

Send the canonical introspection query with no authentication, no side effects, and
no aliasing. Keep the response size bounded by piping straight into a counter:

```
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -X POST \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}' https://target.example/graphql
```

The `__typename` probe separates "endpoint exists and speaks GraphQL" from a generic
JSON 404 without transferring anything. A `406`, `400` with "Unknown field", or a
non-JSON body means the endpoint is not GraphQL at all.

Then confirm introspection is on by requesting schema types only, and immediately
count them rather than saving:

```
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name kind}}}"}' https://target.example/graphql \
  | python3 -c "import json,sys; print(len(json.load(sys.stdin)['data']['__schema']['types']))"
```

A response containing hundreds of type names is conclusive.

## 3. FIELD-LEVEL ENUMERATION WITHOUT DUMPING THE SCHEMA

Use targeted selections to test for specific sensitive fields rather than
downloading the whole schema into your terminal:

```
curl -s -X POST -H 'Content-Type: application/json' -d '{"query":"
{__schema{queryType{fields{name description args{name type{name kind ofType{name}}}}}}}"}' \
  https://target.example/graphql \
  | python3 -c "
import json,sys
for f in json.load(sys.stdin)['data']['__schema']['queryType']['fields']:
    print(f['name'], '->', ','.join(a['name'] for a in f['args']))"
```

Field names alone are the deliverable. Do not execute those fields — querying
`users` or `internalReport` may return real records, and mutations must never be
sent during enumeration.

## 4. IDENTIFYING SENSITIVE SURFACE FROM NAMES

Classify by naming signal only. High-concern root fields and types:

- Access control: `admin`, `users`, `roles`, `permissions`, `impersonate`, `apiKeys`
- Financial: `payments`, `invoices`, `balance`, `payouts`, `subscriptions`
- Credentials-adjacent: `tokens`, `sessions`, `resetPassword`, `mfa`, `otp`
- Bulk or unbounded: `allUsers`, `search`, `export`, `bulkDelete`, `rawQuery`

Counting them is enough for severity. The pairing of a nested type with a
`Boolean` `isAdmin`-style flag on a root-level mutation is a strong authorization
review trigger for the follow-on phase.

## 5. REMEDIATION VERIFICATION

- Disable introspection in production (`introspection: false` in Apollo Server;
  `graphql.introspection=false` on Spring for GraphQL) or gate it behind an
  authenticated staff role.
- Remember that disabling introspection is not access control. Per-field and
  per-type authorization is still required.
- Remove introspection-rejection messages from client-facing errors; detailed
  "introspection is not allowed" text confirms the endpoint exists and is GraphQL.
- Keep schema validation enabled to reject fields rather than silently erroring.
- Apply query depth, complexity, and alias batching limits at the gateway.

## 6. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Enumeration means
`__schema`, `__type`, and `__typename` only. Never send a `mutation`, never query a
business field name discovered in the schema, and never run alias batching or
recursive alias queries to amplify output — those are separate DoS test cases. Do not
pipe the raw schema into external schema-rendering sites, which may persist it.
Report type counts and the names of sensitive root fields, not the full schema.

## Sources
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- GraphQL introspection spec: https://spec.graphql.org/October2021/#sec-Schema-Introspection
- OWASP GraphQL cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
