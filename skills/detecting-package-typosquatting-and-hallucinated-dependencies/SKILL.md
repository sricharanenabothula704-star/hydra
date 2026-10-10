---
name: detecting-package-typosquatting-and-hallucinated-dependencies
description: >-
  Detect typosquat packages and AI-hallucinated dependencies in lockfiles and manifests using edit-distance analysis, registry metadata heuristics, and install-time execution checks.
---

# SKILL: Detect typosquat packages and AI-hallucinated dependencies in lockfiles and manifests using edit-distance analysis, registry metadata heuristics, and install-time execution checks.

> **AI LOAD INSTRUCTION**: Load when reviewing package.json, requirements.txt, go.mod, or Cargo.toml for suspicious dependency names before or during a build.

## 0. RELATED ROUTING
- [exploiting-dependency-confusion-private-package-takeover](#) for registry-resolution abuse
- [detecting-malicious-npm-packages](#) for post-install payload analysis
- [implementing-semgrep-for-custom-sast-rules](#) for CI gate authoring

## 1. TWO DISTINCT PROBLEMS

**Typosquatting** - a real human typos your package name into a lookalike that
the attacker owns. Classic targets: `reqests`, `python-dateutil` vs
`python-dateutils`, `crossenv`, `lodahs`.

**Hallucinated (slopsquatting) dependencies** - an LLM confidently invents a
plausible-sounding package that does not exist, or one that exists but was never
intended. The realistic attack is that the invented name *later gets registered
by someone else*, and the lockfile now points at attacker-controlled code.

Both are caught by the same three checks: name similarity, registry metadata,
and install-time execution surface.

## 2. EXTRACT THE DEPENDENCY SET

```bash
node -e "const p=require('./package.json');console.log([...Object.keys({...p.dependencies,...p.devDependencies})].join('\n'))"
grep -oE '^[A-Za-z0-9_.-]+' requirements.txt | sort -u
awk '/^require/{print $2}' go.mod 2>/dev/null
grep -A20 '^\[dependencies\]' Cargo.toml | grep '=' | cut -d= -f1
```

## 3. EDIT-DISTANCE AND KEYBOARD PROXIMITY

```bash
python3 - <<'EOF'
import itertools
def lev(a,b):
    prev=list(range(len(b)+1))
    for i,ca in enumerate(a,1):
        cur=[i]
        for j,cb in enumerate(b,1):
            cur.append(min(prev[j]+1,cur[j-1]+1,prev[j-1]+(ca!=cb)))
        prev=cur
    return prev[-1]

deps=["reqests","python-dateutils","crossenv","lodash","urllib3","lodashash"]
canon=["requests","python-dateutil","cross-env","lodash","urllib3","lodash"]
for d,c in zip(deps,canon):
    dist=lev(d.lower(),c.lower())
    if dist and dist<=2:
        print(f"SUSPECT {d!r} ~ {c!r}  distance={dist}")
EOF
```

Distance 1 against a popular target is high confidence; distance 2 is a warning.

## 4. REGISTRY METADATA HEURISTICS

```bash
# Exists? Age? Downloads? Maintainer count?
npm view <pkg> --json | jq '{name,created:.time.created,modified:.time.modified,
  versions,maintainers:[.maintainers[].name]}'
curl -sS "https://pypi.org/pypi/<pkg>/json" | jq '{version:.info.version,
  uploaded:.releases[.info.version][0].upload_time, home:.info.home_page}'

# Diff the upstream date vs local
date -u -d "$(npm view <pkg> time.created)" +%F
```

High-signal signals for a malicious package: `created` within the last 30 days,
very high download count concentrated in a single version, a single maintainer,
and a homepage that differs by a character from the canonical project.

## 5. INSTALL-TIME EXECUTION SURFACE

```bash
npm view <pkg> scripts --json
npm pack <pkg> --dry-run 2>&1 | head -40
grep -nE 'setup_requires|cmdclass|__init__' -r <pkg>

# Inspect the tarball; never execute it
curl -sS "$(npm view <pkg> dist.tarball)" | tar tzf - | head -50
```

A package whose install script spawns a process, reads `~/.aws`, or phones home
is malicious regardless of how innocent its README looks.

## 6. PINNING AND ENFORCEMENT

- Commit lockfiles; require `--frozen-lockfile` / `npm ci` / `--require-hashes`.
- Mirror dependencies into an internal proxy registry with allowlisting.
- Fail CI when a new dependency was published within the last 30 days.
- Scan lockfiles for any package name absent from the approved internal list.

## 7. RESPONSIBLE TESTING

Analysis only. Do **not** `npm install` or `pip install` a suspected malicious
package - that runs its install script on your machine. Inspect the tarball
statically (`npm pack`, `pip download --no-deps`, or the registry's file
list) and report names and hashes. Never register or claim a package name.

## Sources
- https://research.swtch.com/package-hallucination
- https://cwe.mitre.org/data/definitions/1357.html
- https://owasp.org/www-project-dependency-check/
