# BugBounty MCP integration

HYDRA setup installs and connects the upstream
[BugBounty MCP Server](https://github.com/gokulapap/bugbounty-mcp-server) to
OpenCode over local stdio. It is pinned to upstream commit
`47b096fe7d18ffa2cf257d20a1a87ec0abebca20` (version 2.2.0), not a HYDRA-authored
server. It exposes 53 tools, nine guidance resources, and five reusable prompts.
The upstream source, tests, documentation, and license are retained in
`~/.config/opencode/mcp/bugbounty-mcp-server`.

## Safe defaults

- The OpenCode MCP entry is enabled so its 53 tools, resources, and prompts are
  available in OpenCode.
- It starts with `SAFE_MODE=true` and an empty `ALLOWED_TARGETS`; network tools
  therefore reject all targets until an operator explicitly configures scope.
- Nuclei and the Subfinder, Amass, Assetfinder, and gau adapters remain disabled.
- Private-address targets remain disabled. Request pacing, concurrency, and
  port-count defaults are reduced in the OpenCode config.
- Finding data and report output are stored under
  `~/.local/share/opencode/bugbounty-mcp/`, not in the current project.
- Stdio is used; no network-facing MCP listener is started.

The MCP server has its own `ALLOWED_TARGETS` setting, separate from HYDRA's
`SCOPE_ALLOWLIST.txt`. Keep the MCP setting empty by default. If an authorized
program requires network tools, configure only its approved hosts in the
`bugbounty` MCP `environment` block in `~/.config/opencode/opencode.jsonc`.
Do not enable external adapters or Nuclei until their binaries and behavior have
been reviewed.

## Install and checks

`setup.sh` clones the fixed upstream commit, creates an isolated Python 3.10+
virtual environment, installs the package, and validates it with the target
scope explicitly empty. It refuses to overwrite an existing MCP directory that
is not the expected repository at the pinned commit. To inspect the install:

```bash
~/.config/opencode/mcp/bugbounty-mcp-server/.venv/bin/bugbounty-mcp validate-config
~/.config/opencode/mcp/bugbounty-mcp-server/.venv/bin/bugbounty-mcp list-tools
```

The upstream suite currently has Windows-specific failures in POSIX permission
and process-group tests. HYDRA's installer uses Bash and targets Linux/WSL; the
optional process adapters stay disabled by default.
