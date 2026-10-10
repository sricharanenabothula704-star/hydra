---
name: detecting-graphql-deep-nesting-resource-exhaustion-cost
description: >-
  Detecting GraphQL query-cost abuse: deep nesting, batching, and complexity-based DoS. Covers alias-based amplification, query complexity limits, and safe load-controlled testing.
---

# SKILL: Detecting GraphQL query-cost abuse: deep nesting, batching, and complexity-based DoS. Covers alias-based amplification, query complexity limits, and safe load-controlled testing.

> **AI LOAD INSTRUCTION**: Load when assessing a GraphQL endpoint for DoS via nested queries, aliases, or batching. Covers complexity/depth limiting, introspection cost, and how to test with bounded, low-volume requests so you don't take down a production API.

## 0. RELATED ROUTING
- [exploiting-graphql-depth-limit-denial-of-service](#) for the depth-specific case
- [detecting-api-graphql-batch-query-amplification](#) for batch arrays
- [detecting-api-pagination-parameter-resource-exhaustion](#) for non-GraphQL cost abuse

## 1. THE COST AMPLIFIERS

- **Depth:** nested relations cause N+1 database queries per level.
- **Aliases:** `a: user(1){...} b: user(1){...} ...` repeat expensive work hundreds of times in one document.
- **Batching:** an array of N queries multiplies server work.
- **Introspection + fragments** inflating parse cost.

## 2. DEFENSES TO CHECK

- Max query depth (e.g. Apollo/Graphene depth limiting)
- Max query complexity/cost (weighted by field cost)
- Alias/field caps, batch-size caps
- Per-request timeout, query allowlist (only approved operations)
- Rate limiting per token/user

## 3. SAFE TESTING

Test at LOW volume so you don't impact a production API:

1. Send a moderately nested query (depth ~10-20) and observe timing.
2. Send one bounded alias fan-out (e.g. 50 aliases) — measure, don't escalate to thousands.
3. Stop well before causing real degradation. The goal is to show *super-linear* cost, not to DoS.

Never fire unbounded amplification against production. Confirm with timing deltas at modest scale.

## 4. IMPACT FRAMING

Report the amplification factor and the missing limit, plus the theoretical unbounded impact. Include your conservative test parameters so the reviewer knows you stayed within safe bounds.

## 5. REMEDIATION

- Enforce depth + complexity limits server-side (not just client hints).
- Cap aliases and batch sizes.
- Use DataLoader/batching to collapse N+1 rather than relying on limits alone.
- Query allowlisting for known expensive operations; per-user rate limits; timeouts.

## Sources
- CWE-400: https://cwe.mitre.org/data/definitions/400.html
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- Apollo resource limits: https://www.apollographql.com/docs/apollo-server/performance/
