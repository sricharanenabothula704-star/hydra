#!/usr/bin/env python3
"""HYDRA skill-sync — additive-only installer/updater for skill modules.

Safely merges skills from a SOURCE directory into a TARGET directory
(default: ~/.config/opencode/skills). Never overwrites existing files;
customized/local skills always win.

Usage:
  python3 skills_sync.py <source_skills_dir> [--target ~/.config/opencode/skills] [--log FILE]
"""
import argparse, shutil, sys, time
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="directory containing skill folders")
    ap.add_argument("--target", default=str(Path.home() / ".config/opencode/skills"))
    ap.add_argument("--log", default=None)
    a = ap.parse_args()

    src = Path(a.source).expanduser().resolve()
    tgt = Path(a.target).expanduser().resolve()
    if not src.is_dir() or src == tgt:
        sys.exit(f"[!] bad source: {src}")

    added, skipped, files_added = [], [], 0
    for d in sorted(src.iterdir()):
        if not d.is_dir():
            continue
        dest = tgt / d.name
        if dest.exists():
            skipped.append(d.name)
            continue
        shutil.copytree(d, dest)
        added.append(d.name)
        files_added += sum(1 for x in dest.rglob("*") if x.is_file())

    lines = [
        "# Skill Sync Log — ADDITIVE ONLY",
        f"# {time.strftime('%Y-%m-%d %H:%M')}  source={src}",
        f"# added_dirs={len(added)} files_added={files_added} skipped_existing={len(skipped)}",
    ]
    lines += [f"+ {n}" for n in added]
    lines += [f"= kept-existing: {n}" for n in skipped]
    report = "\n".join(lines)

    log_path = Path(a.log) if a.log else tgt.parent / "SKILL_SYNC_LOG.md"
    log_path.write_text(report + "\n")
    print(report[:2000])
    print(f"\n[OK] +{len(added)} skills → {tgt}")
    print(f"[OK] log: {log_path}")

if __name__ == "__main__":
    main()
