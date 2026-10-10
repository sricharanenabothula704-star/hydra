---
name: detecting-drupal-config-sync-service-account-exposure
description: >-
  Detect exposed Drupal config-sync service accounts, API keys, and JSON:API config import endpoints.
---

# SKILL: Detect exposed Drupal config-sync service accounts, API keys, and JSON:API config import endpoints.

> **AI LOAD INSTRUCTION**: Load when auditing Drupal 8+ sites, reviewing Config Sync deployment pipelines, or hunting leaked deployment credentials.

## 0. RELATED ROUTING
- [detecting-secrets-in-repositories](#) for the git-history half of the same exposure
- [hardening-api-key-security-controls](#) for scoped, rotated key design after exposure
- [detecting-graphql-schema-introspection-disabled-bypass](#) for alternate metadata surface on Drupal
- [api-recon-and-docs](#) for enumerating contributed JSON:API modules and their routes

## 1. STACK AND VERSION FINGERPRINT (PASSIVE)

```bash
curl -s https://target.tld/ -D- -o /dev/null | grep -iE 'x-generator|x-drupal|x-powered-by'
curl -s https://target.tld/core/CHANGELOG.txt | head -5
curl -s https://target.tld/update.php | head -5
curl -s https://target.tld/CHANGELOG.txt | head -3
```

An empty CHANGELOG/CHANGELOG.txt with a `Drupal` generator meta tag indicates Core 10.x (retired files).
A present `core/CHANGELOG.txt` means 9.x or earlier, which still supports the legacy `update.php` module
enable endpoint.

## 2. THE CONFIG SYNC CREDENTIAL MODEL

Config Sync stores its service-account key in `settings.php` under `config_sync.settings`:

```php
$settings['config_sync']['key'] = getenv('CONFIG_SYNC_KEY');
```

Older and many still-common deployments hardcode it. Search the deployed tree and git history:

```bash
grep -rn "config_sync.settings" . | head
git log -p --all -S "config_sync.settings" --oneline | head -40
git grep -n "DEFAULT_SETTINGS\|DEFAULT_KEY" $(git rev-list --all) -- settings.php 2>/dev/null | head
```

Testcontainers and Drush containers commonly bake the key into image layers and CI variable dumps.

## 3. KEY VALIDATION READ-ONLY

A valid config-sync key can be exercised **without mutating anything** by requesting the settings
resource for a known config object. A wrong key yields 403; a valid key yields data.

```bash
KEY=$(grep -oP "(?<=DEFAULT_KEY = ')[^']+" settings.php)
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "X-CSRF-Token: anon" -H "X-Drupal-Token: anon" \
  "https://target.tld/jsonapi"            # baseline anonymous

curl -s -D- -H "X-Drupal-Token: $KEY" \
  "https://target.tld/jsonapi" | grep -iE 'HTTP/|x-drupal-cache|content-type'
```

A `200` with a `X-Drupal-Token` header and expanded JSON:API resource links means the key is live.
Do **not** POST `/jsonapi/config` or `/config/{name}` — that would overwrite configuration.
Read-only `GET /jsonapi/config` listing is sufficient proof and is safe.

## 4. JSON:API ENDPOINT EXPOSURE CHECK

```bash
for p in jsonapi config core/config sync/config/update status.php update.php install.php; do
  printf '%-28s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' https://target.tld/$p)"
done
```

Red flags: `/config/*` returning 200 anonymously, `/update.php` reachable (enables arbitrary module
enable → RCE), `/jsonapi?resource=drupal__system` leaking mail/email templates to anonymous callers.

## 5. ENUMERATION AND PRIVILEGE DELTAS

```bash
# Anonymous-visible resources vs authenticated-visible resources
curl -s 'https://target.tld/jsonapi' | jq -r '.links[].href' | sort -u > /tmp/anon.txt
curl -s -H "Authorization: Bearer $STAGING_JWT" 'https://target.tld/jsonapi' \
  | jq -r '.links[].href' | sort -u > /tmp/auth.txt
comm -13 /tmp/anon.txt /tmp/auth.txt
```

Compare `user.role`, `user.user`, and `filter.*` schemas: anonymous access to `user.role` or
`user.user` with `filter[status]` exposed is an information-disclosure path to privilege escalation.

## 6. RESPONSIBLE TESTING BOUNDARY

Do all enumeration and token validation read-only. Config Sync keys are **write-capable by design**;
treating a found key as a credential to rotate rather than a payload to fire is the right posture.
Only on explicitly authorized systems, and only against a staging clone, validate write capability
with `drush config:export --simulate` locally rather than a remote import. If your engagement requires
proof-of-write, use an OOB callback in the destination value so the confirmation lands off-target and
no production config is changed.

## 7. REMEDIATION

Move `config_sync.settings.key` to a secret manager injected at deploy time, scope the key to a
non-human deploy identity with a short expiry, remove `update.php` and `install.php` from production,
disable the `update` module's anonymous UI, gate `/jsonapi` per-resource, and rotate any key that ever
touched git history. Add `config_sync.settings` to secret-scanning rules so future commits fail the build.

## Sources
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
- CWE-522: https://cwe.mitre.org/data/definitions/522.html
- Drupal Config Sync documentation: https://www.drupal.org/docs/core-modules-and-themes/core-modules/config-module
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
