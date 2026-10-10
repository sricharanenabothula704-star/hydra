---
name: detecting-graphql-schema-introspection-disabled-bypass
description: >-
  Detect GraphQL schemas where introspection is disabled but the API surface remains fully enumerable.
---

# SKILL: Detect GraphQL schemas where introspection is disabled but the API surface remains fully enumerable.

> **AI LOAD INSTRUCTION**: Load when assessing GraphQL APIs, triaging disabled introspection as a control, or enumerating query surface.

## 0. RELATED ROUTING
- [graphql-and-hidden-parameters](#) for schema discovery and hidden-field testing
- [api-authorization-and-bola](#) for the authorization gaps introspection merely reveals
- [detecting-spring-boot-actuator-misconfiguration](#) for the same "discovery blocked, surface open" pattern
- [api-recon-and-docs](#) for endpoint discovery across the whole surface

## 1. FINGERPRINT FIRST

```bash
curl -s -D- -o /dev/null https://target.tld/graphql | grep -iE 'server:|x-powered-by'
curl -s -H 'Content-Type: application/json' -d '{"query":"{__typename}"}' https://target.tld/graphql
curl -s -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name}}}"}' https://target.tld/graphql
```

A `200` with `{"data":{"__schema":...}}` means introspection is live. `"Introspection is disabled"` from
Apollo Server, or a `__schema` field error from graphql-js, means the control is in place. Distinguish
*disabled* from *unauthorized* — the first errors for everyone, the second errors only without creds.

## 2. WHY DISABLING INTROSPECTION IS NOT A CONTROL

Introspection is a documentation feature, not an access control. Production GraphQL clients (Apollo,
urql, graphql-request) need the schema at build time, so it is frequently available from:

- A bundled schema artifact on a CDN, or `/schema.graphql` from a dev proxy left in place
- A staging or UAT host on the same domain that never had introspection disabled
- The mobile/desktop app bundle, which embeds a schema for offline operation
- Error messages, which leak field names for any invalid query

## 3. BYPASS TECHNIQUES THAT STAY READ-ONLY

```bash
CT='Content-Type: application/json'; U=https://target.tld/graphql
# @skip directive that many servers still honor
curl -s -H "$CT" -d '{"query":"{ __schema { queryType { name } } } @skip(if:false)"}' $U
# Field-name suggestion channel (did-you-mean)
curl -s -H "$CT" -d '{"query":"{ __schemae { queryType { name } } }"}' $U | jq .
# Typo suggestions enumerate field/type names
curl -s -H "$CT" -d '{"query":"{ usrs { id } }"}' $U | jq -r '.errors[].message'
# __type can work even with full introspection off
curl -s -H "$CT" -d '{"query":"{ __type(name:\"User\"){ name fields { name } } }"}' $U
```

A "did you mean `users`?" error is a partial schema leak and is sufficient evidence that disabling
introspection provides no real protection.

## 4. ENUMERATE THE SURFACE WITHOUT INTROSPECTION

```bash
for f in user users me viewer node search; do
  printf '%-8s %s\n' "$f" \
    "$(curl -s -H "$CT" -d "{\"query\":\"{ $f { id } }\"}" $U | jq -c '.errors[0].message // "OK"')"
done
for p in graphql graphiql playground altair voyager api/graphql; do
  curl -s -o /dev/null -w "$p:%{http_code}\n" https://target.tld/$p
done
```

Different error wording across fields distinguishes existing fields from nonexistent ones. Also test a
`.graphql` GET with `?query=`. A live `/graphiql` on production is a finding on its own.

## 5. THE REAL FINDING: AUTHORIZATION, NOT DISCOVERY

Once the field surface is known, test whether authorization is enforced **per-object** — where GraphQL
most often fails. Two identities, same field, different ids; both must not succeed:

```bash
curl -s -H 'Authorization: Bearer $TOKEN_A' -H 'Content-Type: application/json' \
  -d '{"query":"{ user(id:\"<B-owned-id>\"){ email } }"}' https://target.tld/graphql
curl -s -H 'Authorization: Bearer $TOKEN_B' -H 'Content-Type: application/json' \
  -d '{"query":"{ user(id:\"<A-owned-id>\"){ email } }"}' https://target.tld/graphql
```

Both returning data is a BOLA finding regardless of introspection state. Depth limits are the other
control to verify, using a static query that resolves no real work:

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"query":"{ a { b { c { d { e { f { g { h { i { j { k { id } } } } } } } } } } } }"}' \
  https://target.tld/graphql | jq '.errors[0].message'
```

## 6. RESPONSIBLE TESTING BOUNDARY

Do not treat introspection-disable as a security control in a report you issue, nor as a blocker to
testing. All techniques above are read-only queries against production-safe endpoints. Avoid expensive
alias-batching attacks (thousands of aliases in one query) against systems you are not authorized to
load-test — that is a self-inflicted DoS. Never dump whole object types containing other users' PII;
bound queries to a single field on an object you own.

## 7. REMEDIATION

Keep introspection disabled as defense in depth, but treat it as noise reduction, not control. Enforce
authorization at the resolver layer with field- and object-level checks plus a DataLoader scoping
lookups to the authenticated principal. Set `maxDepth`, `maxAliases`, `maxComplexity`, and restrict
batching at the gateway. Ship GraphiQL/Playground only behind auth and off-production. Alert on high
alias counts or depth, and on queries naming types absent from the intended schema.

## Sources
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- Apollo Server disabling introspection: https://www.apollographql.com/docs/apollo-server/security/disabling-introspection
