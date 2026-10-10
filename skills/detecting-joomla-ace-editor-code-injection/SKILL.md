---
name: detecting-joomla-ace-editor-code-injection
description: >-
  Detect Joomla code editor plugins that expose arbitrary PHP file write from the web interface.
---

# SKILL: Detect Joomla code editor plugins that expose arbitrary PHP file write from the web interface.

> **AI LOAD INSTRUCTION**: Load when assessing Joomla sites, reviewing legacy editor extensions, or hunting web shells planted via file managers.

## 0. RELATED ROUTING
- [detecting-file-upload-and-web-shell-persistence](#) for post-exploitation artifact hunting
- [ssti-server-side-template-injection](#) for the OGNL/template analogue in the PHP stack
- [unauthorized-access-common-services](#) for exposed admin panels on default installs
- [performing-web-application-logging-with-modsecurity](#) for WAF coverage of PHP write endpoints

## 1. WHY ACE EDITOR MATTERS

Ace/CodeMirror Joomla editors write to disk from a browser session. Their historical flaws reduce to
one shape: a path plus content from the client with a capability check missing, or satisfied by "logged
in at all" rather than Super User.

```bash
curl -s https://target.tld/ -D- -o /dev/null | grep -iE 'x-powered-by|server'
curl -s https://target.tld/administrator/ -o /dev/null -w 'admin:%{http_code}\n'
curl -s https://target.tld/api/index.php/v1/config/application -D- | grep -i 'x-ratelimit\|HTTP/'
```

The REST `/api/index.php/v1` surface is a good low-noise fingerprint for the Joomla major version
(`?public=false` vs `?public=true` variants changed in 4.x).

## 2. IDENTIFY INSTALLED EDITORS

```bash
# Public component manifests
curl -s https://target.tld/plugins/system/ -o /dev/null -w '%{http_code}\n'
curl -s https://target.tld/media/system/js/fields/joomla-tinymce.js -o /dev/null -w 'tinymce:%{http_code}\n'
```

From a source or backup copy:

```bash
find . -path ./cache -prune -o -name '*.xml' -print | xargs grep -l 'aceeditor\|codemirror\|ace' 2>/dev/null | head
grep -rniE 'plg_aceeditor|plg_codeeditor|mod_ace' plugin*/language/en-GB/*.ini 2>/dev/null | head
```

Editor manifests in `plugins/<group>/<name>/<name>.xml` list the file extensions each editor claims —
`xml|json|css|scss|less|js|php` in one row is the classic dangerous configuration.

## 3. READ-ONLY REACHABILITY PROBING

Never write to a production site to test this. Confirm the handler exists and its auth posture using
non-mutating verbs and invalid-but-inert paths:

```bash
curl -s -X OPTIONS -D- -o /dev/null 'https://target.tld/index.php?option=com_ajax&format=json'
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  'https://target.tld/index.php?option=com_aceeditor' \
  -d 'filename=README.txt&content=probe'
curl -s -D- -o /dev/null 'https://target.tld/index.php?option=com_config&view=component&layout=editor'
```

A `200` with a JSON body for the unauthenticated save call is a confirmed critical finding on its own —
no payload execution is needed to prove it. Capture the response body as evidence.

## 4. PATH TRAVERSAL IN THE FILENAME PARAMETER

Editors commonly concatenate `basePath + userFilename`. Test with inert, harmless values only:

```bash
for p in '../../configuration.php' '../../.htaccess' '../../../etc/passwd'; do
  curl -s -X POST 'https://target.tld/index.php?option=com_editor&task=save' \
    --data-urlencode "filename=$p" --data-urlencode 'content=x' \
    -o /dev/null -w "$p -> %{http_code}\n"
done
```

Blocking traversal before any permission check (`403` even when unauthenticated) is a mitigation; a
`200`/`500` difference between `README.txt` and `../../configuration.php` proves unguarded server-side
path handling.

## 5. POST-COMPROMISE ARTIFACT HUNTING

Once an editor has been abused, the filesystem tells the story:

```bash
find . -name '*.php' -newermt '-90 days' -not -path './cache/*' | head -30
grep -rniE 'eval\(|assert\(|base64_decode\(|preg_replace\(.*/e' --include=*.php . | head -30
# Compare media/ and templates/ file counts against the packaged manifest
ls -la media/ templates/ images/ | head -40
```

Files under `images/`, `tmp/`, or `cache/` containing PHP tags are near-certain post-exploitation.

## 6. RESPONSIVE TESTING BOUNDARY

Fingerprint and probe reachability with invalid, inert values first. Any test that would persist a PHP
file must run only on systems where you hold explicit written authorization and a change ticket, and
must be removed in the same engagement window with a documented before/after hash of the directory.
When only a proof-of-concept is needed, prefer an OOB callback embedded in the *content* of a text file
whose name ends in `.txt` — it confirms the write path fires without leaving executable code on target.

## 7. REMEDIATION

Remove unused editor plugins, upgrade to a supported Joomla release, restrict file-editing actions to
Super User, disable unused `com_ajax` task paths, add file integrity monitoring on `media/`, `images/`,
`templates/`, and audit the Super User account list quarterly.

## Sources
- CWE-94: https://cwe.mitre.org/data/definitions/94.html
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- Joomla Security Centre: https://security.joomla.org/
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
