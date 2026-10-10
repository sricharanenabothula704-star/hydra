#!/usr/bin/env python3
"""Check that the searchable skill index matches files in this checkout."""

from collections import Counter
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
INDEX_PATH = SKILLS_DIR / "index.json"


def main() -> int:
    try:
        index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read skills/index.json: {exc}")
        return 1

    entries = index.get("skills")
    if not isinstance(entries, list):
        print("ERROR: skills/index.json must contain a 'skills' list")
        return 1

    errors = []
    names = [entry.get("name") for entry in entries]
    if any(not isinstance(name, str) or not name for name in names):
        errors.append("every skill entry needs a non-empty string name")

    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        errors.append(f"duplicate names: {', '.join(duplicates)}")

    indexed = set(names)
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            continue
        skill_file = SKILLS_DIR / name / "SKILL.md"
        if not skill_file.is_file():
            errors.append(f"{name}: missing {skill_file.relative_to(ROOT).as_posix()}")
        if not (entry.get("description") or "").strip():
            errors.append(f"{name}: empty description")

    on_disk = {
        path.parent.name for path in SKILLS_DIR.rglob("SKILL.md") if path.is_file()
    }
    for name in sorted(on_disk - indexed):
        errors.append(f"{name}: SKILL.md exists but is absent from index.json")

    total = index.get("total")
    if total != len(entries):
        errors.append(
            f"total is {total!r}, but skills list contains {len(entries)} entries"
        )

    expected_summary = Counter(entry.get("category", "other") for entry in entries)
    summary = index.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be a category-count object")
    elif dict(expected_summary) != summary:
        errors.append(
            f"summary counts do not match skill entries: expected {dict(expected_summary)}"
        )

    if errors:
        print(f"Skill index validation failed ({len(errors)} issue(s)):")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(
        f"Skill index OK: {len(entries)} entries match {len(on_disk)} SKILL.md files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
