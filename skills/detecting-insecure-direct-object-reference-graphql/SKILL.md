---
name: detecting-insecure-direct-object-reference-graphql
description: >-
  Detect IDOR within GraphQL resolvers, where nested nodes and arguments expose objects without an ownership check even when the top-level query is authorized.
---

# SKILL: Detect IDOR within GraphQL resolvers, where nested nodes and arguments expose objects without an ownership check even when the top-level query is authorized.

> **AI LOAD INSTRUCTION**: Load when a target exposes a GraphQL endpoint (introspection, errors, or an app using GraphQL) and you are assessing object-level authorization across the type graph.

## 0. RELATED ROUTING
- [detecting-broken-object-level-authorization-bola](#) for the REST framing of the same defect
- [performing-graphql-introspection-attack](#) for enumerating the schema and type graph first
- [detecting-idor-sequential-identifier-enumeration](#) for the ID predictability angle

## 1. WHY GRAPHQL CHANGES THE GAME

In REST each endpoint is its own authorization decision. In GraphQL one request traverses the
entire object graph via nested resolvers, and every field/argument is a potential unauthorized
accessor. Developers who check the root query frequently forget nested resolvers and arguments
that select objects directly. Introspection also hands an attacker the map of where to try.

## 2. ENUMERATE THE TYPE GRAPH

If introspection is enabled, dump it — this is the attacker's map:

```bash
curl -s -X POST https://target/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}' \
  | jq '.data.__schema.types[] | select(.fields!=null) | {t:.name, f:[.fields[].name]}'
```

Types whose resolvers take an `id`/`ID`/`nodeId` argument are direct object fetchers and the
primary IDOR candidates. With introspection disabled, infer structure from field-level errors
and client bundles.

## 3. DIRECT NODE FETCHING

Global Relay-style node lookups are the classic GraphQL IDOR: `node(id:)` fetches any object
by opaque global ID with no ownership check.

```bash
# A's session fetching B's node
curl -s -X POST https://target/graphql \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK_B" \
  -d '{"query":"query($id:ID!){ node(id:$id){ __typename ... on Order { id total status } } }","variables":{"id":"<A_NODE_ID>"}}' | jq .
```

A `200` returning A's order confirms horizontal IDOR at the node resolver.

## 4. ARGUMENT-BASED OBJECT ACCESS

Many queries take an object ID argument and fetch without scoping to the caller:

```graphql
query($userId: ID!) { user(id: $userId) { id email balance } }
```

Pass A's ID while authenticated as B. "Not found" means a check exists; a full object means
none. Watch resolvers that fall back to "the current user" when the argument is absent — the
guard only works if it validates a *supplied* argument, so always pass the foreign ID.

## 5. NESTED RESOLVER TRAVERSAL

Even with a guarded root, nested fields may fetch fresh objects. Try:

```graphql
query($id: ID!) {
  order(id: $id) {
    id
    customer { id email paymentMethods { last4 } }   # nested cross-object leak
    invoices { id pdfUrl }
    internalNotes { body author }
  }
}
```

The root `order` may be ownership-checked while `customer` or `invoices` are not. Any non-null
payload for a field that should be owner-bound is a leak.

## 6. IMPACT AND REPORTING

- Reading another user's PII, balances, or notes → High/Critical by sensitivity.
- Mutating without an ownership check → High. Leaking private object URLs (PDFs) → data
  exposure.

Report per resolver with the exact query, the two identities used, and returned field names.
One unguarded resolver pattern usually repeats across the schema.

## 7. DETECTION & HARDENING

- Enforce ownership in **every** resolver that accepts an object ID; wrap object fetchers in
  a single authorization-aware data loader scoped to the current principal/tenant.
- Scope `node`/`nodes` and list resolvers to `owner_id = principal.id` at the data layer.
- Make ownership mandatory-by-default via an allowlist of public fields.
- Disable introspection in production (reconnaissance gold, though not the fix).
- Add cross-account resolver regression tests and enable resolver-level authorization
  logging/alerting on denials.

## 8. RESPONSIBLE TESTING NOTE

Use only the test identities and objects provided for this engagement; never traverse into
other tenants' or real users' data. Query for the minimum fields needed to prove the resolver
returns *something* it should not, and stop — do not paginate through a leaked collection.
Avoid mutations against foreign objects; a read-only field proving missing ownership is
sufficient evidence and far safer. If introspection is disabled, do not treat it as a blocker
to report or attempt to bypass aggressively — schema inference from error messages on your own
account is enough. Destructive or data-exporting queries require explicit written authorization.

## Sources
- CWE-639: https://cwe.mitre.org/data/definitions/639.html
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- OWASP API1 BOLA: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- PortSwigger GraphQL vulnerabilities: https://portswigger.net/web-security/graphql
