#!/usr/bin/env python3
"""Verify the Apache-2.0 skill modules against a pinned upstream commit.

``skills/ATTRIBUTION.json`` claims that 808 modules are derived from
``mukul975/Anthropic-Cybersecurity-Skills``. This script makes that claim
checkable later, by anyone, without trusting this repository's own account of
itself.

It fetches the upstream repository at a pinned commit and compares module by
module. Offline checks -- the ones that run in CI -- are in
``scripts/verify_skill_attribution.py``; this one needs network access, so it
is run deliberately rather than on every build.

Usage::

    # Check the commit recorded in the manifest.
    python scripts/verify_skill_provenance.py

    # Check a specific upstream commit.
    python scripts/verify_skill_provenance.py --against 54a7988

    # Check whether some *other* commit is a better match for our copies.
    python scripts/verify_skill_provenance.py --scan-refs --best-of 5

Exit codes: 0 every module matches upstream byte for byte, 1 otherwise,
2 the upstream repository could not be reached.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "skills" / "ATTRIBUTION.json"
DEFAULT_REPO = "https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git"


def _norm(data: bytes) -> bytes:
    """Normalise line endings so a CRLF checkout does not read as a difference."""
    return data.replace(b"\r\n", b"\n")


def _index(root: pathlib.Path) -> dict[str, list[pathlib.Path]]:
    out: dict[str, list[pathlib.Path]] = {}
    for path in root.rglob("SKILL.md"):
        out.setdefault(path.parent.name, []).append(path)
    return out


def _fetch(commit: str, repo: str) -> pathlib.Path:
    """Clone upstream and check out ``commit``. Raises on failure."""
    workdir = tempfile.mkdtemp(prefix="hydra-provenance-")
    target = pathlib.Path(workdir) / "upstream"
    subprocess.run(
        ["git", "clone", "--quiet", repo, str(target)],
        check=True,
        capture_output=True,
    )
    checkout = subprocess.run(
        ["git", "-C", str(target), "checkout", "--quiet", commit],
        check=False,
        capture_output=True,
        text=True,
    )
    if checkout.returncode != 0:
        # Shallow-ish fallback: fetch the object directly.
        fetched = subprocess.run(
            ["git", "-C", str(target), "fetch", "--quiet", "origin", commit],
            check=False,
            capture_output=True,
            text=True,
        )
        if fetched.returncode != 0:
            raise RuntimeError(
                f"cannot check out {commit}: {checkout.stderr.strip()} "
                f"/ {fetched.stderr.strip()}"
            )
        subprocess.run(
            ["git", "-C", str(target), "checkout", "--quiet", commit],
            check=True,
            capture_output=True,
        )
    return target


def compare(ours: pathlib.Path, upstream_root: pathlib.Path) -> tuple[int, list[str]]:
    """Return ``(matching, differing_skill_names)`` for every listed module."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    upstream_index = _index(upstream_root / "skills")
    matching = 0
    differing: list[str] = []
    for entry in manifest["modules"]:
        name = entry["skill"]
        local = ours / name / "SKILL.md"
        remote_files = upstream_index.get(name)
        if not local.is_file() or not remote_files:
            differing.append(name)
            continue
        if _norm(local.read_bytes()) == _norm(remote_files[0].read_bytes()):
            matching += 1
        else:
            differing.append(name)
    return matching, differing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--against",
        default=None,
        help="upstream commit to check (default: the manifest's)",
    )
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument(
        "--scan-refs",
        action="store_true",
        help="test the N most recent upstream commits and report "
        "the best match, instead of only the pinned one",
    )
    parser.add_argument("--best-of", type=int, default=5)
    ns = parser.parse_args(argv)

    if not MANIFEST.is_file():
        print("skills/ATTRIBUTION.json not found; run verify_skill_attribution.py")
        return 2
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    upstream_meta = manifest.get("upstream", {})
    total = len(manifest.get("modules", []))

    ours = REPO_ROOT / "skills"

    try:
        if ns.scan_refs:
            target = _fetch("HEAD", ns.repo)
            commits = subprocess.run(
                [
                    "git",
                    "-C",
                    str(target),
                    "log",
                    "--format=%H",
                    f"-{max(1, ns.best_of)}",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.split()
            results = []
            for commit in commits:
                subprocess.run(
                    ["git", "-C", str(target), "checkout", "--quiet", commit],
                    check=True,
                    capture_output=True,
                )
                matching, differing = compare(ours, target)
                results.append((matching, commit, differing))
                print(f"  {matching}/{total} match  {commit[:12]}")
            results.sort(reverse=True)
            best, best_commit, differing = results[0]
            print()
            print(f"best match: {best}/{total} at {best_commit}")
            if differing:
                print(f"still differing ({len(differing)}): {differing[:10]}")
            return 0 if not differing else 1

        commit = ns.against or upstream_meta.get("verified_against_commit")
        if not commit:
            print("no commit pinned in the manifest; pass --against <sha>")
            return 2
        print(f"checking {total} modules against upstream {commit[:12]}")
        target = _fetch(commit, ns.repo)
        matching, differing = compare(ours, target)
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"could not reach upstream: {exc}", file=sys.stderr)
        return 2

    if differing:
        print(f"MISMATCH: {matching}/{total} match, {len(differing)} differ")
        for name in differing[:20]:
            print(f"  {name}")
        return 1

    print(
        f"PROVENANCE OK: {matching}/{total} modules byte-identical to upstream "
        f"{commit[:12]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
