---
name: detecting-graphql-federation-service-tenant-escape
description: >-
  Detecting authorization boundaries that break across GraphQL Federation subgraphs. Covers `_entities`/`_service` exposure, missing propagation of auth context, and cross-tenant data via federation.
---

# SKILL: Detecting authorization boundaries that break across GraphQL Federation subgraphs. Covers `_entities`/`_service` exposure, missing propagation of auth context, and cross-tenant data via federation.

> **AI LOAD INSTRUCTION**: Load when a GraphQL API is federated across multiple subgraphs. Covers how auth/context propagation failures between gateway and subgraphs leak data across services/tenants, and how to test for it safely.

## 0. RELATED ROUTING
- [detecting-broken-object-level-authorization-bola](#) for the single-service BOLA case
- [exploiting-graphql-introspection-authorization-bypass](#) for introspection/authz gaps
- [detecting-insecure-direct-object-reference-graphql](#) for IDOR in GraphQL

## 1. FEDERATION STRUCTURE

A supergraph gateway resolves queries against multiple **subgraphs**. The gateway holds the global schema; each subgraph enforces its own auth. The risk: the gateway resolves a field the subgraph assumed was already authorized, or auth context (headers, user claims) is not propagated.

## 2. THE EXPLOITABLE MISMATCH

1. Gateway exposes a query across subgraphs A and B.
2. Subgraph A checks "is user X allowed to read resource R?"
3. The gateway fetches R's identity and then asks subgraph B for the actual data **without re-checking** that user X may see R.

Result: an ID from subgraph A (a resource the user legitimately owns or can reference) yields data from subgraph B they shouldn't see. Classic cross-service BOLA.

## 3. SAFE TESTING

Use your own test account and your own entities. Create a resource you own, then attempt to reach a sibling/other-user resource **via your own account only**. Do not access other real users' data. Compare gateway response vs direct-subgraph response to spot missing auth.

## 4. DETECTION CHECKLIST

- Is the gateway resolving `_entities` with representations the client controls? (type + id pairs)
- Does each subgraph independently authorize, or does it trust a header the gateway forwards?
- Are `@key`/`@requires` fields exposing identifiers that another service trusts unchecked?

## 5. REMEDIATION

- Enforce authorization in **every** subgraph, not only the gateway.
- Propagate and validate auth context (subject claims) end-to-end; don't rely on a spoofable forwarded header.
- Never let a client-supplied `_entities` representation bypass the service that owns the object.
- Restrict introspection and federation metadata in production.

## Sources
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- Apollo Federation docs: https://www.apollographql.com/docs/federation/
