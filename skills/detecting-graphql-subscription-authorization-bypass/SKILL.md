---
name: detecting-graphql-subscription-authorization-bypass
description: >-
  Detect unauthorized access to GraphQL subscriptions and WebSocket channels over long-lived connections.
---

# SKILL: Detect unauthorized access to GraphQL subscriptions and WebSocket channels over long-lived connections.

> **AI LOAD INSTRUCTION**: Load when reviewing GraphQL WS/SSE subscription authorization and connection-scoped filtering.

## 0. RELATED ROUTING
- [detecting-api-graphql-batch-query-amplification](#) for query-cost and complexity limits
- [websocket-security](#) for WebSocket handshake and CSWSH testing
- [testing-for-broken-access-control](#) for authorization verification baseline

## 1. WHY SUBSCRIPTIONS DIFFER

HTTP requests re-authorize on every call. A subscription is a long-lived channel: a single
authorization decision at connect time governs every future event. Failures concentrate here:

- Auth checked at handshake, never re-checked per event
- Subscription resolver ignores its argument filter and streams the whole collection
- Cross-tenant topics (`tenant:123`) guessable or enumerated by integer
- Reconnect with a stale/expired token accepted because the token is only read once
- No `connection_init` timeout, so unauthenticated sockets accumulate

## 2. TRANSPORT SETUP

Common transports: `graphql-ws` (legacy subscriptions-transport-ws) and `graphql-transport-ws`.
Both use `connection_init` for auth and `subscribe` for operations.

```
wscat -c 'wss://api.example.com/graphql' \
  -H "Authorization: Bearer $MY_TOKEN" \
  -x '{"type":"connection_init","payload":{"authorization":"Bearer '"$MY_TOKEN"'"}}'
```

Use your own token and account. If `Authorization` alone works at the handshake, the proxy
layer is authenticating and the GraphQL layer may be trusting it implicitly.

## 3. SUBSCRIBE TO A FOREIGN TOPIC

Create two tenants in your own workspace, seed records in each, then request a subscription for
the tenant you do not own.

```
{"type":"subscribe","id":"1","payload":{
  "query":"subscription { recordChanged(tenantId:\"TENANT_B\") { id value } }",
  "variables":{}}}

{"type":"subscribe","id":"2","payload":{
  "query":"subscription { recordChanged { id value } }", "variables":{}}}

{"type":"subscribe","id":"3","payload":{
  "query":"subscription { recordChanged(tenantId:$t) { id value } }",
  "variables":{"t":"TENANT_B"}}}
```

Any event containing `TENANT_B` data in the connection owned by `TENANT_A` confirms the bypass.
Note whether rejection happens as an error frame, an empty stream, or silently.

## 4. MISSING ARGUMENT FILTER

If `recordChanged` takes no tenant argument and still emits only your tenant's events, the
resolver is filtering somewhere (good). Verify by making a change in your own tenant B-less
fixture and confirming you receive it, and by confirming you never receive B's changes.

## 5. ENUMERATION AND TOPIC GUESSING

```
for i in 1 2 3 100 999; do
  {"type":"subscribe","id":"t$i","payload":{
    "query":"subscription { recordChanged(tenantId:\"$i\") { id } }","variables":{}}}
done
```

Integer topic names allow discovery of other tenants. Prefer opaque, non-sequential topic
identifiers bound to server-side entitlements.

## 6. TOKEN EXPIRY AND RECONNECT

1. Connect with a short-lived token.
2. Let the token expire.
3. Keep the socket open and trigger events in your own tenant.
4. Then attempt a `reconnect` (protocol message `connection_retry` / client-driven reconnect).

A server that keeps streaming after expiry, or that accepts the stale token on reconnect,
has no session lifecycle. Check also whether `connection_init_ack` has a timeout; the
`graphql-transport-ws` spec uses `connectionInitWaitTimeout`.

## 7. FIX RECOMMENDATIONS

1. Authorize in the subscription resolver against the authenticated principal, not just the
   handshake; filter every event by the tenant/owner from the session.
2. Use opaque topic identifiers and verify server-side entitlement on every subscribe frame.
3. Enforce `connection_init` timeout and reject unauthenticated sockets promptly.
4. Re-validate authorization per event or on a short interval; close sockets when an account's
   access is revoked.
5. Set per-connection limits: max subscriptions, idle timeout, and a global
   concurrent-connection cap keyed by principal.
6. Never put tenant identity in a client-controlled argument without a server-side scope check.

## 8. RESPONSIBLE TESTING

Run every test against your own workspace with two tenants you created and synthetic records.
Confirm exposure by receiving your own seeded data, never by reading another organization's
events. Do not stress connection limits, and obtain written authorization before assessing any
third-party GraphQL service.

## Sources
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
- CWE-285: https://cwe.mitre.org/data/definitions/285.html
- graphql-ws protocols: https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md
- OWASP WebSocket Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
