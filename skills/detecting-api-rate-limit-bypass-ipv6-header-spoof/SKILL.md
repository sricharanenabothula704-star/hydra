---
name: detecting-api-rate-limit-bypass-ipv6-header-spoof
description: >-
  Detect API rate-limit bypass via forwarded-header spoofing and IPv6 address rotation.
---

# SKILL: Detect API rate-limit bypass via forwarded-header spoofing and IPv6 address rotation.

> **AI LOAD INSTRUCTION**: Load when assessing whether a public API enforces per-client throttling against header and address-identity spoofing.

## 0. RELATED ROUTING
- [performing-api-rate-limiting-bypass](#) for the full bypass methodology
- [implementing-api-rate-limiting-and-throttling](#) for control design reference
- [hunting-anomalous-authentication-patterns](#) for correlation with auth telemetry

## 1. WHY RATE LIMITING FAILS

Most gateways key a throttle bucket on a single value the client controls, or on the raw
socket peer, which is a shared NAT/proxy address. Common weak keys:

- `X-Forwarded-For` first hop (client-supplied), `X-Real-IP`, `X-Client-IP`, `Forwarded`
- `X-Originating-IP`, `True-Client-IP`, `CF-Connecting-IP`
- IPv6 addresses rotate within a /64 (RFC 6177, RFC 6603), so per-address buckets never fill

## 2. SETUP

Use an account or API key you own and a dedicated fixture. Record the documented quota first.

```
curl -s -D- -o /dev/null -H "Authorization: Bearer $MY_TOKEN" \
  https://api.example.com/v1/items | grep -i -E 'ratelimit|retry-after|x-r'
```

Note baseline headers: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`,
`X-RateLimit-*`, `Retry-After`, and the `429` body shape.

## 3. HEADER SPOOFING TESTS

Add headers one at a time and watch whether quota decrements per request or stays flat.

```
# leftmost spoof
curl -H "X-Forwarded-For: 203.0.113.77" https://api.example.com/v1/items
# chain injection
curl -H "X-Forwarded-For: 10.0.0.1, 198.51.100.9" https://api.example.com/v1/items
# competing header names
curl -H "X-Real-IP: 203.0.113.77" -H "True-Client-IP: 203.0.113.78" \
     -H "CF-Connecting-IP: 203.0.113.79" -H "X-Client-IP: 203.0.113.80" \
     https://api.example.com/v1/items
# RFC 7239 standard header
curl -H 'Forwarded: for=203.0.113.77;proto=https;by=203.0.113.10' \
     https://api.example.com/v1/items
```

```
for i in $(seq 1 60); do
  curl -s -o /dev/null -w "%{http_code} " \
    -H "X-Forwarded-For: 198.51.100.$i" \
    https://api.example.com/v1/search?q=test
done; echo
```

| Observation | Likely cause |
|---|---|
| Never a 429 | Bucket keyed on spoofable header, or limiter absent on route |
| 429 only after N per header value | Correct keying, but identity itself is spoofable |
| 429 vanishes when header removed | Leftmost value trusted without proxy validation |
| Distinct limits per token AND per IP | Correct layered design |

## 4. IPV6 ROTATION TEST

A single /64 yields effectively unlimited addresses and clients commonly implement RFC 6980
temporary addresses. Verify the limiter keys on the account or key, not the address.

```
curl -6 --interface $IFACE -H "X-Forwarded-For: 2001:db8:1:2::1"   https://api.example.com/v1/items
curl -6 --interface $IFACE -H "X-Forwarded-For: 2001:db8:1:2::2"   https://api.example.com/v1/items
curl -6 --interface $IFACE -H "X-Forwarded-For: 2001:db8:1:2::ffff" https://api.example.com/v1/items
```

Also test parser-divergent encodings: `::ffff:198.51.100.9`, fully expanded
`2001:DB8:0000:...:0001`, and zone-id forms `2001:db8::1%25eth0`.

## 5. TRUST BOUNDARY CROSS-CHECKS

- Compare the actual client IP the server derives with the header you sent; a match means spoofing works.
- Confirm which proxy/CDN ranges are in the trusted list and whether direct-to-origin bypasses it.
- Check for denylist checks like `str_contains($ip, $blocked)`, bypassable by
  `1.2.3.4.`, `01.2.3.4`, `2130706433`, `0x7f.0.0.1`, `[::1]`.

## 6. CONTROL RECOMMENDATIONS

1. Strip inbound forwarding headers at the edge; resolve identity only from the trusted proxy chain.
2. Layer buckets: API key, principal, source IP, ASN. The strictest wins.
3. For IPv6, normalize to the /64 prefix rather than the full 128-bit address.
4. Use token-bucket or sliding-window limits with `Retry-After` and backoff guidance in the 429 body.
5. Alert on low distinct-client-per-request ratios and high cardinality of client-supplied IPs.

## 7. RESPONSIBLE TESTING

Confirm only against accounts, keys, and network ranges you own or have written authorization to
test. Keep volume under any documented quota ceiling. Never aim to exhaust a shared or
third-party service's limits; stop immediately if you observe load on infrastructure that is not
yours.

## Sources
- CWE-770: https://cwe.mitre.org/data/definitions/770.html
- CWE-441: https://cwe.mitre.org/data/definitions/441.html
- RFC 7239: https://www.rfc-editor.org/rfc/rfc7239
- OWASP API4: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
