# Optional Playwright MCP

HYDRA includes an **opt-in** Playwright MCP entry for browser-based UI and
client-side validation. It is disabled in the generated OpenCode config by
default. It is not a bot-detection bypass, stealth browser, or scope-enforcement
mechanism.

## Enable it

Use OpenCode's `/playwright-setup` command for the approval-based setup flow, or
copy [`AI_PLAYWRIGHT_MCP_SETUP_PROMPT.md`](AI_PLAYWRIGHT_MCP_SETUP_PROMPT.md)
into an OpenCode agent. The command/prompt does not install or enable anything
without your approval.

1. Install Node.js 18 or newer and the Chromium browser dependencies required by
   Playwright on your system.
2. Review the pinned package `@playwright/mcp@0.0.83` and its official security
   documentation before use.
3. In `~/.config/opencode/opencode.jsonc`, change only
    `mcp.playwright.enabled` from `false` to `true`, then restart OpenCode.

After enabling the MCP, use `/browser-check https://your-authorized-host` for a
scope-gated browser validation workflow. The command stops if the MCP is not
enabled, the local allowlist rejects the host, authorization is unclear, or a
bot challenge/CAPTCHA/rate limit is encountered.

The configured server runs headless, uses an isolated in-memory browser context,
and blocks service workers. It does not attach to your regular browser profile
or reuse its cookies. The package is launched through `npx` when enabled.

## Safe use

- Before every navigation, run HYDRA's scope checker against the exact host and
  confirm that the written authorization covers browser testing. The MCP server
  itself does **not** enforce the local allowlist.
- Prefer local test apps or explicitly authorized targets. Do not enter
  production credentials or load saved cookies/storage state into this isolated
  context.
- Use Playwright to inspect rendered DOM, console/network behavior, and validate
  a finding on an in-scope application. Do not use stealth plugins, spoofed
  fingerprints, proxy rotation, CAPTCHA solving, or other bot-detection evasion.
- If a site presents a CAPTCHA, bot challenge, rate limit, or access denial, stop
  and report the block; do not try to circumvent it.
- Playwright MCP is a powerful browser-control tool, not a security boundary.
  Keep the OpenCode MCP server local (the supplied stdio configuration does
  this) and review tool behavior and data flows before enabling it.

Official project: <https://github.com/microsoft/playwright-mcp>.
