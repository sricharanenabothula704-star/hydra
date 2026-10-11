# AI-assisted Playwright MCP setup prompt (Process 2)

Copy this prompt into OpenCode from the HYDRA repository when you want an AI
agent to guide the optional Playwright MCP setup. It is designed to perform
checks and prepare changes with approval gates; it cannot guarantee a
"perfect" installation on every machine.

```text
Set up HYDRA's optional Playwright MCP from the correct repository.

Project identity:
- GitHub repository: sricharanenabothula704-star/hydra
- Canonical URL: https://github.com/sricharanenabothula704-star/hydra
- Canonical clone command: `git clone https://github.com/sricharanenabothula704-star/hydra.git`
- Setup guide: `docs/PLAYWRIGHT_MCP.md` in that repository.

First verify that the current workspace is the HYDRA repository by checking
its `README.md`, `docs/PLAYWRIGHT_MCP.md`, and (when available)
`git remote get-url origin`. Do not assume a similarly named project is HYDRA.
If the repository is not already available, show the canonical clone command
and ask before cloning or downloading it. If the origin points elsewhere, stop
and ask me what to do.

Safety rules:
- This is for normal browser-based validation on local or explicitly
  authorized targets. It is NOT a bot-detection bypass. Do not install stealth
  add-ons, spoof fingerprints, rotate proxies, solve CAPTCHAs, or work around
  rate limits, bot challenges, or access denials.
- Do not navigate to any target during installation or verification. Use only
  a local test page if a smoke test is needed.
- Do not read, import, or reuse browser profiles, cookies, storage-state files,
  or production credentials. The configured server must stay isolated.
- Explain every planned command and config edit first. Ask before installing
  software, downloading npm packages or browser binaries, or changing config.
- Never overwrite an existing OpenCode config. Before an approved edit, make a
  timestamped backup, show its path, and merge only the Playwright MCP entry.
- Never use sudo/administrator privileges. If system browser dependencies
  require elevation, stop and explain options instead of escalating.

Steps:
1. Read `docs/PLAYWRIGHT_MCP.md`, the Playwright MCP project's official
   installation/security docs, and the current OpenCode config. Report the OS,
   shell, Node/npm/npx versions, OpenCode version, and whether MCP is already
   configured. Do not print secrets.
2. Confirm Node.js 18+ is available. If not, explain the official installation
   options and wait for approval before installing it.
3. Inspect the pinned `@playwright/mcp@0.0.83` package metadata to identify its
   matching Playwright dependency and browser-install command. Show the exact
   package versions and commands; do not use `@latest` or an unpinned browser
   package. Ask for approval before downloading either package or browser.
4. Back up the existing `~/.config/opencode/opencode.jsonc`. Merge only the
   `mcp.playwright` entry from `opencode.jsonc.template`, preserving all user
   settings. The entry must remain `enabled: false` unless I explicitly ask to
   enable it. Do not enable any stealth, fingerprint spoofing, proxy, persistent
   profile, extension/CDP attach, or unrestricted file access option.
5. Validate the resulting JSONC and show the diff. If validation fails, restore
   the backup and stop. Do not silently overwrite or regenerate the whole file.
6. Only after approval, install the matching Chromium browser dependencies if
   needed. Verify MCP status without navigating to a public target. If a safe
   local test page is unavailable, report that the browser launch was not
   smoke-tested rather than claiming it works.
7. Keep the server disabled until I explicitly approve enabling it. Explain
   that Playwright MCP does not enforce HYDRA's scope allowlist: before every
   later navigation, check the exact host with `~/scripts/scope_check.sh` and
   confirm written authorization includes browser testing.

Stop and report any mismatch, unexpected config, download error, or permission
prompt. Do not continue by guessing.
```
