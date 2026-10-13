#!/usr/bin/env python3
"""Verify that every Apache-2.0 skill module carries upstream attribution.

808 of the 1,179 modules in ``skills/`` originate from
``mukul975/Anthropic-Cybersecurity-Skills`` (Apache-2.0). Apache-2.0 section 4
requires that redistribution carry the license, retain the source attribution
notices, and mark modified files. Those requirements are easy to state and easy
to silently violate when the corpus is regenerated, so they are checked here
instead of trusted.

Checks performed (all offline, no network):

1. The upstream license text is present and is byte-identical to the copy
   recorded in the attribution manifest.
2. Every module listed in ``skills/ATTRIBUTION.json`` exists and still declares
   the license the manifest claims for it.
3. Every module in the corpus that declares ``license: Apache-2.0`` appears in
   the manifest. An unlisted Apache module is a redistribution with no
   attribution record, which is the exact failure this script exists to catch.
4. Every attributed module records an upstream author.

Exit codes: 0 all checks passed, 1 one or more checks failed.

Usage::

    python scripts/verify_skill_attribution.py
    python scripts/verify_skill_attribution.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
MANIFEST = SKILLS_DIR / "ATTRIBUTION.json"
LICENSE_FIELD = re.compile(r"^license:\s*(.+)$", re.MULTILINE)
AUTHOR_FIELD = re.compile(r"^author:\s*(.+)$", re.MULTILINE)
APACHE = "Apache-2.0"


def _frontmatter_fields(path: pathlib.Path) -> dict[str, str]:
    """Return the simple ``key: value`` frontmatter fields of a SKILL.md."""
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    block = text[:end] if end != -1 else text
    fields: dict[str, str] = {}
    for line in block.splitlines():
        if line.startswith((" ", "\t", "#")) or ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip() in {"license", "author"}:
            fields[key.strip()] = value.strip()
    return fields


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check() -> tuple[list[dict], list[dict]]:
    """Return ``(checks, failures)`` for the attribution contract."""
    checks: list[dict] = []
    failures: list[dict] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})
        if not ok:
            failures.append({"check": name, "detail": detail})

    # --- manifest present and parseable -------------------------------------
    if not MANIFEST.is_file():
        record("manifest_present", False, f"missing {MANIFEST.relative_to(REPO_ROOT)}")
        return checks, failures
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        record("manifest_present", False, f"{MANIFEST.name} is not valid JSON: {exc}")
        return checks, failures
    record("manifest_present", True, f"{MANIFEST.name} parsed")

    upstream = manifest.get("upstream", {})
    entries = manifest.get("modules", [])

    # --- upstream license text ----------------------------------------------
    license_rel = upstream.get("license_text", "LICENSES/Apache-2.0.txt")
    license_path = REPO_ROOT / license_rel
    if not license_path.is_file():
        record("license_text_present", False, f"missing {license_rel}")
    else:
        blob = license_path.read_bytes().replace(b"\r\n", b"\n")
        digest = hashlib.sha256(blob).hexdigest()
        expected = upstream.get("license_sha256")
        if expected is None:
            record(
                "license_text_present",
                True,
                f"{license_rel} present ({len(blob)} bytes)",
            )
        else:
            ok = digest == expected
            record(
                "license_text_present",
                ok,
                f"{license_rel} sha256 {'matches' if ok else 'DIFFERS FROM'} manifest",
            )
        if b"Apache License" not in blob:
            record(
                "license_text_is_apache",
                False,
                f"{license_rel} is not the Apache License text",
            )
        elif "Apache-2.0" not in str(upstream.get("license", "")):
            record(
                "license_text_is_apache", False, "manifest does not declare Apache-2.0"
            )
        else:
            record("license_text_is_apache", True, "Apache License 2.0 text confirmed")

    # --- recorded modules exist and match ------------------------------------
    recorded: dict[str, dict] = {}
    mismatched: list[str] = []
    missing: list[str] = []
    authorless: list[str] = []

    for entry in entries:
        name = entry.get("skill", "<unnamed>")
        rel = entry.get("path") or f"skills/{name}/SKILL.md"
        recorded[name] = entry
        path = REPO_ROOT / rel
        if not path.is_file():
            missing.append(rel)
            continue
        fields = _frontmatter_fields(path)
        if fields.get("license", "").strip() != entry.get("license", "").strip():
            mismatched.append(
                f"{name}: frontmatter={fields.get('license')!r} manifest={entry.get('license')!r}"
            )
        if not fields.get("author", "").strip():
            authorless.append(name)

    record(
        "recorded_modules_present",
        not missing,
        f"{len(entries) - len(missing)}/{len(entries)} modules found"
        + (f"; missing {missing[:3]}" if missing else ""),
    )
    record(
        "recorded_license_matches",
        not mismatched,
        f"{len(entries) - len(mismatched)}/{len(entries)} declare the recorded license"
        + (f"; e.g. {mismatched[0]}" if mismatched else ""),
    )
    record(
        "author_attribution_retained",
        not authorless,
        f"{len(entries) - len(authorless)}/{len(entries)} carry an author: field"
        + (f"; e.g. {authorless[0]}" if authorless else ""),
    )

    # --- no unrecorded Apache modules ----------------------------------------
    strays: list[str] = []
    scanned = 0
    for skill_md in SKILLS_DIR.rglob("SKILL.md"):
        fields = _frontmatter_fields(skill_md)
        scanned += 1
        if fields.get("license", "").strip() == APACHE:
            if skill_md.parent.name not in recorded:
                strays.append(skill_md.parent.name)

    record(
        "no_unattributed_apache_modules",
        not strays,
        f"{scanned} modules scanned; {len(strays)} Apache-2.0 modules missing from the manifest"
        + (f"; e.g. {strays[:3]}" if strays else ""),
    )

    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable output"
    )
    args = parser.parse_args()

    checks, failures = check()

    if args.json:
        print(
            json.dumps(
                {
                    "ok": not failures,
                    "checks": checks,
                    "failures": failures,
                },
                indent=2,
            )
        )
        return 1 if failures else 0

    width = max((len(c["check"]) for c in checks), default=10)
    for c in checks:
        print(f"{'PASS' if c['ok'] else 'FAIL'}  {c['check']:<{width}}  {c['detail']}")
    print()
    if failures:
        print(f"ATTRIBUTION FAILED: {len(failures)} check(s) failed.")
        return 1
    print(f"ATTRIBUTION OK: {len(checks)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
