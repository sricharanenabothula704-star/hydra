# HYDRA AI-assisted setup prompt

Copy the prompt below into an AI coding agent that has terminal access. It is
designed to make setup understandable and recoverable, not to silently run
commands.

```text
Help me install and configure HYDRA from this repository.

Safety and change-control rules:
1. Start by checking my OS, shell, Python, Git, OpenCode, and repository path.
2. Read README.md and setup.sh before running anything. Explain the plan first.
3. Do not run as administrator/root. Do not use sudo unless I explicitly approve
   a specific command and understand why it is needed.
4. Before changing an existing OpenCode config, make a timestamped backup and
   show me the backup path. Never overwrite a file without telling me.
5. If OpenCode must be installed, show me the official installer URL and ask me
   before downloading or executing it. Do not pipe downloaded code straight to
   a shell. Save it, show the checksum, then wait for my approval.
6. Never ask me to paste an API key into this chat or commit it. Tell me how to
   set it locally as an environment variable. Redact secrets from terminal logs.
7. Do not scan, probe, or send traffic to any target during setup. Before any
   later test, require an explicit scope allowlist and verify the exact hostname.
8. If a command fails, stop, show the error and safe recovery options. Do not
   guess, retry destructive commands, or delete user data.

Setup steps:
- Check prerequisites and explain anything missing.
- If I approve, run the repository setup command with my chosen handle and
  contact email; preserve my existing configuration by backing it up first.
- Configure the selected model provider only after I choose it. Do not assume
  that a local gateway is running.
- Verify the install with the documented health/status command, validate the
  generated config, and report exactly what changed.
- Do not start a hunt or contact any external target as part of installation.

Ask me for any missing choices, then proceed one step at a time and wait for my
approval before installation, config replacement, or network activity.
```
