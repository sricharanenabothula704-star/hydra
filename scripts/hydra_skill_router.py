#!/usr/bin/env python3
"""Select skill files for an agent task; this tool reads metadata only."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INDEXES = (
    ROOT / "skills" / "index.json",
    Path.home() / ".config" / "opencode" / "skills" / "index.json",
)
BASELINE = ("scope-guard", "js-analysis")
BASELINE_FILES = {
    "javascript-analysis-methodology": (
        "RECON/05_javascript_analysis.md",
        "JavaScript endpoint, source-map, secret, and frontend analysis methodology; loaded for every task as requested.",
    )
}
STOP = {
    "a",
    "an",
    "and",
    "any",
    "for",
    "from",
    "how",
    "in",
    "is",
    "of",
    "on",
    "or",
    "the",
    "to",
    "use",
    "with",
    "target",
    "task",
    "check",
    "find",
}
ALIASES = {
    "javascript": {"js", "javascript", "node", "frontend", "source-map"},
    "xss": {"cross-site", "scripting", "stored", "reflected", "dom"},
    "sqli": {"sql", "injection", "database", "query"},
    "ssrf": {"server-side", "request", "forgery", "url-fetch", "metadata"},
    "ssti": {"template", "injection", "jinja", "twig", "freemarker"},
    "idor": {"bola", "object-level", "authorization", "access-control"},
    "jwt": {"json-web-token", "token", "jwk", "jku", "algorithm-confusion"},
    "oauth": {"oidc", "redirect-uri", "pkce", "authorization-code"},
    "xxe": {"xml", "external-entity", "soap", "svg"},
    "cve": {"cve", "vulnerability", "patch", "version"},
    "cwe": {"cwe", "weakness", "vulnerability"},
    "api": {"rest", "graphql", "grpc", "endpoint"},
    "mobile": {"android", "ios", "apk", "ipa", "webview"},
    "cloud": {"aws", "azure", "gcp", "metadata", "iam", "s3"},
    "report": {"reporting", "writeup", "submission", "cvss", "cwe"},
}


def _tokens(text: str) -> set[str]:
    tokens = set(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", text.lower()))
    tokens.update(t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in STOP)
    expanded = set(tokens)
    for key, values in ALIASES.items():
        if key in tokens or any(value in tokens for value in values):
            expanded.add(key)
            expanded.update(values)
    return expanded - STOP


def _index_path(explicit: Optional[str] = None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    for candidate in DEFAULT_INDEXES:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "skills/index.json not found in the repo or OpenCode skills directory"
    )


def select_skills(
    task: str, index_path: Optional[str] = None, limit: int = 5
) -> List[Dict[str, object]]:
    """Return mandatory baseline plus the best task-relevant skill modules."""
    if not task.strip():
        raise ValueError("task description cannot be empty")
    path = _index_path(index_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    skills = data.get("skills", [])
    by_name = {item.get("name"): item for item in skills if item.get("name")}

    missing_baseline = [name for name in BASELINE if name not in by_name]
    if missing_baseline:
        raise ValueError(
            "required baseline skill missing from index: " + ", ".join(missing_baseline)
        )

    task_tokens = _tokens(task)
    baseline = list(BASELINE)
    ranked: List[Tuple[float, str]] = []
    for item in skills:
        name = item["name"]
        if name in baseline:
            continue
        skill_tokens = _tokens(
            name.replace("-", " ") + " " + (item.get("description") or "")
        )
        shared = task_tokens & skill_tokens
        if not shared:
            continue
        # Name matches carry extra weight; descriptions provide contextual routing.
        name_tokens = _tokens(name.replace("-", " "))
        score = len(shared) / max(1, len(task_tokens))
        score += 0.75 * len(task_tokens & name_tokens) / max(1, len(task_tokens))
        ranked.append((score, name))

    ranked.sort(key=lambda item: (-item[0], item[1]))
    chosen = baseline + [name for _, name in ranked[: max(0, limit)]]
    result = []
    root = path.parent
    for name in chosen:
        item = by_name[name]
        skill_file = root / name / "SKILL.md"
        if not skill_file.is_file():
            raise FileNotFoundError(f"indexed skill has no file: {skill_file}")
        result.append(
            {
                "name": name,
                "path": str(skill_file),
                "description": item.get("description", ""),
                "mandatory": name in baseline,
            }
        )
    for name, (relative, description) in BASELINE_FILES.items():
        skill_file = root / relative
        if not skill_file.is_file():
            raise FileNotFoundError(f"mandatory baseline file missing: {skill_file}")
        result.append(
            {
                "name": name,
                "path": str(skill_file),
                "description": description,
                "mandatory": True,
            }
        )
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--task", required=True, help="One-sentence description of the agent task"
    )
    parser.add_argument("--index", help="Optional path to skills/index.json")
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum relevant skills to add (default: 5)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )
    args = parser.parse_args(argv)
    try:
        selected = select_skills(args.task, args.index, args.limit)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Skill routing failed: {exc}")
        return 2
    if args.json:
        print(
            json.dumps(
                {"task": args.task, "skills": selected}, indent=2, ensure_ascii=False
            )
        )
        return 0
    print("Skill router — read every returned file in full before acting.")
    for item in selected:
        tag = "MANDATORY" if item["mandatory"] else "RELEVANT"
        print(f"[{tag}] {item['name']} — {item['path']}")
        if item["description"]:
            print(f"  {item['description']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
