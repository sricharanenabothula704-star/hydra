# Third-party notices

## Skill modules declaring Apache-2.0 — PROVENANCE UNRESOLVED

**808 of the 1,179 modules in `skills/` declare `license: Apache-2.0` in their
YAML frontmatter.** They are not covered by the repository's root MIT license.

Apache-2.0 §4(a) requires that recipients receive a copy of the License. The
required text is now included at
[`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt).

**What is still unresolved.** These 808 modules arrived in a bulk import. No
record in this repository identifies the upstream project, its copyright
holder, or whether it carried an attribution or NOTICE requirement. Unlike the
`opencode-skills-cve.zip` import, there is no import note describing their
origin.

Redistributing them may require more than the license text: if the upstream
included a NOTICE file or specific attribution wording, §4(c) and §4(d) oblige
us to carry it forward too, and we cannot reproduce what we cannot identify.

**Action required by the repository owner:** determine the upstream of these
808 modules and either (a) add its NOTICE and attribution to this file, or
(b) remove them. Until then, treat the Apache-licensed subset as
redistribution-blocked.

Any module in `skills/` whose frontmatter reads `license: Apache-2.0` is in
scope for this notice. HYDRA-authored playbooks (`401-403-bypass-techniques`,
the `offensive-*` set, the CVE-specialized set) are not.

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
