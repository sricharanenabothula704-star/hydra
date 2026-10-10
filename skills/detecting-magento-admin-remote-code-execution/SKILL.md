---
name: detecting-magento-admin-remote-code-execution
description: >-
  Detect Magento admin RCE paths including template block injection, layout XML injection, and REST web API flaws.
---

# SKILL: Detect Magento admin RCE paths including template block injection, layout XML injection, and REST web API flaws.

> **AI LOAD INSTRUCTION**: Load when assessing Magento 2 stores, reviewing custom admin controllers, or triaging suspicious admin sessions.

## 0. RELATED ROUTING
- [ssti-server-side-template-injection](#) for the underlying Twig/PUI evaluation primitive
- [detecting-file-upload-and-web-shell-persistence](#) for post-exploitation artifact hunting
- [api-authorization-and-bola](#) for Magento REST and GraphQL authorization scope
- [detecting-graphql-schema-introspection-disabled-bypass](#) for the Commerce GraphQL surface

## 1. FINGERPRINT THE PLATFORM

```bash
curl -s -D- -o /dev/null https://target.tld/ | grep -iE 'x-magento|x-cache|set-cookie'
curl -s https://target.tld/static/version | head -c 40; echo
curl -s -o /dev/null -w 'graphql:%{http_code}\n' -H 'Content-Type: application/json' \
  -d '{"query":"{__typename}"}' https://target.tld/graphql
curl -s -o /dev/null -w 'rest:%{http_code}\n' https://target.tld/rest/V1/products
curl -s -o /dev/null -w 'admin:%{http_code}\n' https://target.tld/admin
```

`/static/version` returns the installed framework version and is the cleanest read-only oracle. Also
check OpenSearch/Elasticsearch exposure, since `/_search` on a misconfiguration leaks order/customer PII:

```bash
curl -s -o /dev/null -w 'es:%{http_code}\n' https://target.tld:9200/_cat/indices
```

## 2. ADMIN AUTH POSTURE

```bash
# Login endpoint must be rate limited and must not leak user enumeration
for u in admin administrator test@example.com nonexistent@nowhere.tld; do
  curl -s -o /dev/null -w "$u -> %{http_code}\n" -X POST \
    https://target.tld/admin/admin/auth/login/ \
    -d "login[username]=$u&login[password]=invalidpw&form_key=invalid"
done
```

Identical status codes and identical response sizes across known-unknown and known-good usernames
indicate no enumeration oracle. Look for the `admin_secure` cookie without `SameSite`/`HttpOnly`, and
for admin panels reachable on IP allowlists that include broad ranges.

## 3. THE CLASSIC RCE PRIMITIVES

**(a) `Magento\Framework\View\Element\Template` filter injection.** Any admin-accessible field that
reaches a template context as an expression string is dangerous. Confirm reachability read-only:

```bash
curl -s -X POST https://target.tld/rest/V1/products \
  -H 'Authorization: Bearer $STAGING_TOKEN' -H 'Content-Type: application/json' \
  -d '{"product":{"sku":"probe","name":"probe","price":1,"attribute_set_id":4,"visibility":4,
       "status":1,"weight":1,"extension_attributes":{"custom_attributes":[{"attribute_code":"description",
       "value":"probe"}]}}}'
```

Read the product back with `GET /rest/V1/products/probe` and inspect which fields were interpreted
rather than stored. CMS block/widget CRUD (`/rest/V1/cmsPage`, `V1/cmsBlock`) is the highest-yield
surface for this class.

**(b) Layout update XML injection.** The classic vector is `custom_layout_update` XML passed to a
block constructor, which then evaluates directives. Test only for *acceptance*, not execution: submit a
layout containing a nonexistent block class and observe whether the response is a clean validation
error or a fatal naming error.

```bash
curl -s -X PUT https://target.tld/rest/V1/cmsPages/3 \
  -H 'Authorization: Bearer $STAGING_TOKEN' -H 'Content-Type: application/json' \
  -d '{"cms_page":{"title":"probe","page_layout":"1_column",
       "custom_layout_update_xml":"<referenceContainer name=\"content\"><block class=\"NonExistent_Probe_Block\"/></referenceContainer>"}}'
```

**(c) GraphQL/`webapi_rest`.** Magento ships both. Disabling GraphQL introspection removes only the
schema-discovery convenience, not the authorization gaps.

## 4. DIFF-BASED CONFIRMATION STRATEGY

The highest-signal, lowest-harm technique for Magento admin RCE is to prove the parser reaches
attacker-controlled markup without executing anything:

1. Snapshot the relevant `cms_page` rows before and after (read-only DB access).
2. Submit structurally-invalid but harmless markup.
3. Confirm server-side parsing via an error only the XML/Template engine could produce.
4. Revert the row from your snapshot.

For hard proof of execution, request an OOB callback (a DNS/HTTP host under your control) rather than a
reverse shell. The callback keeps the target unmodified while proving execution.

## 5. RESPONSIBLE TESTING BOUNDARY

Fingerprint first, then probe reachability with invalid or inert values. Anything that writes CMS
content, layout XML, or product attributes should only be attempted on systems with explicit written
authorization, and only with a pre-captured restore snapshot plus a change record. Never leave test
products, CMS pages, or layout updates behind — Magento's full-page cache will serve your test artifact
to real shoppers until you purge it.

## 6. REMEDIATION

Patch to a supported version, put the admin panel behind VPN or IP allowlist, enforce MFA, replace any
custom module that evaluates admin input into a template/layout context, restrict
`custom_layout_update_xml` to trusted roles, lock down Elasticsearch/OpenSearch, and alert on
`admin/*` and `/rest/V1/*` from non-office source IPs.

## Sources
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- CWE-1336: https://cwe.mitre.org/data/definitions/1336.html
- OWASP Testing Guide - Template Injection: https://owasp.org/www-project-web-security-testing-guide/
- Magento Security Patches: https://experienceleague.adobe.com/en/docs/commerce/security-patches
