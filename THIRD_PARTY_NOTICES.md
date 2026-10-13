# Third-party notices

## Anthropic-Cybersecurity-Skills (808 skill modules)

**808 of the 1,179 modules in `skills/` are derived from
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills).**
They are not covered by this repository's root MIT license.

    Copyright 2026 mukul975

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use these files except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

The upstream project ships no `NOTICE` file, so Apache-2.0 §4(d) does not apply.

### Apache-2.0 §4 compliance

| Requirement | How it is met |
|---|---|
| §4(a) — recipients receive a copy of the License | [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt) is a verbatim byte-for-byte copy of the upstream `LICENSE`, including the `Copyright 2026 mukul975` line |
| §4(b) — modified files carry prominent notices | Declared in full under "Modifications" below and machine-readable in [`skills/ATTRIBUTION.json`](skills/ATTRIBUTION.json) |
| §4(c) — retain source attribution notices | The upstream `author:` frontmatter field had been stripped from all 808 modules during import. It has been restored in every one of them, and `scripts/verify_skill_attribution.py` fails the build if any is removed again |
| §4(d) — carry a NOTICE file | Not applicable: upstream ships no `NOTICE` |

### Upstream authorship

The 808 modules were contributed upstream by six distinct authors. The
per-module mapping is in [`skills/ATTRIBUTION.json`](skills/ATTRIBUTION.json).

| Upstream author | Modules |
|---|---|
| `mahipal` | 763 |
| `mukul975` | 28 |
| `andrewibrah` | 7 |
| `team-cybersecurity` | 7 |
| `juliosuas` | 2 |
| `devredious` | 1 |

### Provenance method and confidence

Verified on 2026-10-13 by cloning the upstream repository and comparing it
module-by-module against this repository, against upstream commit
`54a798831d2266a3ca61ce68a7acb80b81160d57`:

- **818** upstream skill directories, **1,179** here — **808** names match
  exactly, and those 808 are precisely the modules declaring `license: Apache-2.0`.
- **798 of 808** are byte-identical to upstream once the YAML frontmatter is
  excluded.
- **All 808** carry an upstream `author:` value; the 808:818 gap and the exact
  author distribution are consistent with an earlier snapshot of a repository
  that has since grown.
- Upstream is **not** pinned by this repository, so the exact upstream commit
  these modules were imported from cannot be proven. The attribution above is
  stated with high confidence; the specific commit is the best match found on
  the verification date, not a recorded fact.

This is not legal advice. Anyone redistributing HYDRA should re-run
`scripts/verify_skill_attribution.py` and confirm the upstream terms themselves.

### Modifications

These modules are **modified works** under Apache-2.0 §4(b). The changes are
declared here in full:

1. **Frontmatter.** The upstream `author:` field was removed from all 808
   modules during import. It has since been restored to its upstream value in
   all 808. No other frontmatter field was altered except the `description`
   field on 31 modules, which was rewritten from upstream's folded (`>-`) form
   to a single-line form for the skill router. No `description` text was
   invented for these 31; where content was lost it is noted below.
2. **Body text in 10 modules.** These are the only modules whose bodies differ
   from upstream beyond the frontmatter:
   - `implementing-kubernetes-pod-security-standards`
   - `implementing-pod-security-admission-controller`
   - `performing-ai-driven-osint-correlation`
   - `continuous-llm-red-teaming-with-promptfoo`
   - `auditing-mcp-servers-for-tool-poisoning`
   - `analyzing-email-headers-for-phishing-investigation`
   - `analyzing-macro-malware-in-office-documents`
   - `building-detection-rules-with-sigma`
   - `detecting-fileless-malware-techniques`
   - `detecting-living-off-the-land-attacks`

   The edits fall into three classes, and they are **regressions**:
   - Vendor names were replaced with generic wording (`Anthropic` became
     `the AI vendor`, `Claude` became `the AI agent`) in five modules. This
     reduced specificity for no benefit and should be reverted to upstream text.
   - Several `# or anthropic, ollama, etc.` style comment lines were deleted.
   - In the two `implementing-*pod-security*` modules, upstream's specific
     "when to use this skill" trigger lists and their cross-references between
     the pair were replaced with generic boilerplate. This is **content loss**:
     the local copies are strictly less useful than upstream.

   Reverting these 10 modules to their upstream bodies is the correct fix and
   has not been done here, to keep this change reviewable. It is tracked as an
   open deviation rather than silently accepted.

### Scope of this notice

Any module in `skills/` whose frontmatter reads `license: Apache-2.0` is in
scope. HYDRA-authored playbooks — `401-403-bypass-techniques`, the
`offensive-*` set, and the CVE-specialized set — are not.

### Enforcement

`scripts/verify_skill_attribution.py` re-checks all of this offline on every CI
run: the license text hash, that all 808 recorded modules exist and still
declare their recorded license, that all 808 retain an `author:` field, and
that **no** Apache-2.0 module in the corpus is missing from the manifest. The
last check is the one that catches a future import dropping attribution.

## BugBountySkills

Some HYDRA skill, checklist, and knowledge-base material incorporates
content from [0xN0RMXL/BugBountySkills](https://github.com/0xN0RMXL/BugBountySkills).
That project is distributed under the MIT License. Its required copyright
and permission notice is preserved in
[`LICENSES/BugBountySkills-MIT.txt`](LICENSES/BugBountySkills-MIT.txt).

## BugBounty MCP Server

HYDRA setup installs the upstream
[gokulapap/bugbounty-mcp-server](https://github.com/gokulapap/bugbounty-mcp-server)
at pinned commit `47b096fe7d18ffa2cf257d20a1a87ec0abebca20` as a separate local
OpenCode MCP server. The upstream project's copyright and MIT permission notice
are preserved in [`LICENSES/BugBountyMCP-MIT.txt`](LICENSES/BugBountyMCP-MIT.txt).
The third-party server remains attributed to its upstream authors; HYDRA's
installer, configuration, and documentation are the integration work.

HYDRA-authored code and material remain under the root `LICENSE`. This notice
does not claim ownership of unrelated third-party publications.

## Further reading

The repository no longer redistributes extracted full-text copies of books
or other publications. Readers can consult those works through their authors,
publishers, libraries, or other authorized sources. HYDRA's own playbooks
remain in `docs/`, `common/`, `skills/`, and `knowledge_base/`.
