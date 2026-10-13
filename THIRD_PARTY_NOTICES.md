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
| §4(b) — modified files carry prominent notices | Not triggered: the 808 modules are byte-identical to upstream at the pinned commit, so there are no modified files. See "Modifications" for the drift that was reverted |
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

Verified by cloning the upstream repository and comparing it module-by-module
against this repository. The upstream commit is **pinned**:

    mukul975/Anthropic-Cybersecurity-Skills @ 54a798831d2266a3ca61ce68a7acb80b81160d57

At that commit:

- **818** upstream skill directories, **1,179** here. **808** names match
  exactly, and those 808 are precisely the modules declaring
  `license: Apache-2.0`.
- **808 of 808 are byte-identical** to upstream **at commit `54a7988`** once
  line endings are normalised. The copies are faithful, not adapted.

That claim is pinned to that commit and is deliberately **not** phrased as
"identical to upstream", which would silently become false the moment upstream
moves. If the commit is force-pushed, rewritten or deleted, the claim has to be
re-established, not assumed — which is why
`scripts/verify_skill_provenance.py` runs on a schedule.
- All 808 carry the upstream `author:` value; the 808:818 gap and the exact
  author distribution are consistent with an earlier snapshot of a repository
  that has since grown.

The claim is re-checkable rather than merely asserted:

    python scripts/verify_skill_provenance.py                    # against the pinned commit
    python scripts/verify_skill_provenance.py --against <sha>    # against any other commit
    python scripts/verify_skill_provenance.py --scan-refs --best-of 5

This is not legal advice. Anyone redistributing HYDRA should re-run both
verifiers and confirm the upstream terms themselves.

### Modifications

**None.** All 808 modules are byte-identical to upstream at the pinned commit,
so section 4(b) is satisfied by the absence of modification rather than by a
notice.

This was not the initial state, and the correction is worth recording because
this is the kind of drift that goes unnoticed. The original bulk import had:

- **stripped the `author:` field** from all 808 modules, a section 4(c)
  violation. It has been restored from upstream.
- **reformatted the `description` field** on 31 modules from upstream's folded
  (`>-`) form to a single-line form.
- **edited the body of 10 modules**, replacing specific upstream content with
  generic boilerplate. These were regressions, not improvements: vendor names
  were de-branded (`Anthropic` became "the AI vendor", `Claude` became "the AI
  agent"), `# or anthropic, ollama, etc.` comment lines were dropped, and in
  `implementing-kubernetes-pod-security-standards` and
  `implementing-pod-security-admission-controller` upstream's "when to use this
  skill" trigger lists and their cross-references were lost entirely.

All 808 files were restored verbatim from upstream, which removes the
modification question and repairs the content loss at the same time.
`scripts/verify_skill_provenance.py` now enforces it.

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

`scripts/verify_skill_provenance.py` performs the byte-for-byte comparison
against the pinned upstream commit. It needs network access, so it is run
deliberately rather than on every build, and it is what makes the "no
modifications" claim above falsifiable rather than aspirational.

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
