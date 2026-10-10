# OpenCode CVE skill import (2026-10-11)

Imported 200 user-authored skill modules from `opencode-skills-cve.zip` into
`skills/` and registered them in `skills/index.json` under
`cve-specialized`. The archive was supplied by the repository owner and
authorized for publication.

## Checks performed

- Inspected ZIP paths and entry types before extraction; no unsafe paths or
  symbolic links were found.
- Found no duplicate skill names within the archive, no existing skill-name
  collisions, and no byte-identical content matches against the repository.
- Verified the imported files match the archive contents and that every entry
  is present in the index. `python scripts/validate_skill_index.py` passes.
- Screened the Markdown for basic structure, suspicious high-risk terms, and
  common prompt-injection strings. These checks are screening aids, not a
  complete security review.
- Topic-similarity scoring identified related skills; these were retained as
  specialized playbooks rather than treated as exact duplicates. Similarity
  scores are lexical signals and cannot establish semantic equivalence.

The static site skill cards are generated from `skills/index.json` with
`python scripts/generate_skills_page.py <path-to-skills-index.json>` in the
website repository.
