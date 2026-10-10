# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within HYDRA, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **sricharan996@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Security Guidelines

- **Never commit credentials, API keys, or tokens** to the repository
- **Only test targets you are authorized to test** (bug bounty scope, your own systems)
- **HYDRA is for authorized security testing only** — see [DISCLAIMER.md](DISCLAIMER.md)
- All tool installations use best-effort, non-root methods where possible
- The `install-tools.sh` script only installs well-known, open-source security tools

## Scope

This security policy covers the HYDRA framework itself (code, scripts, configurations). It does not cover:
- Third-party tools installed by `install-tools.sh`
- Security of targets you test with HYDRA
- Misuse of the framework for unauthorized access

## Best Practices

1. Run HYDRA in an isolated environment (VM, container)
2. Never run with root privileges unless explicitly required
3. Review all generated commands before execution
4. Keep your installation updated: `git pull origin main`
