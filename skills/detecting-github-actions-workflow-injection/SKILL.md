---
name: detecting-github-actions-workflow-injection
description: >-
  Detecting GitHub Actions workflow script injection via untrusted `${{ github.event.* }}` interpolation into `run:` blocks. Covers the pull_request_target/workflow_run/issue_comment privilege-escalation patterns, static analysis, runtime canary confirmation, and workflow hardening.
---

# SKILL: Detecting GitHub Actions workflow script injection via untrusted `${{ github.event.* }}` interpolation into `run:` blocks. Covers the pull_request_target/workflow_run/issue_comment privilege-escalation patterns, static analysis, runtime canary confirmation, and workflow hardening.

> **AI LOAD INSTRUCTION**: Load when you need to audit a repository's GitHub Actions workflows for injection via untrusted input (PR titles, comments, branch names, issue bodies) reaching `run:` steps, or to detect exploitation of an already-compromised workflow.

## 0. RELATED ROUTING
- [securing-github-actions-workflows](#) for the full workflow hardening model
- [cross-site-request-forgery-in-github-workflows](#) for the pwn-request privilege pattern
- [supply-chain-security-for-build-pipelines](#) for broader CI integrity
- [secrets-scanning-and-prevention-in-ci-cd](#) for token/secret exposure

## 1. THE INJECTION PRIMITIVE

GitHub expands `${{ ... }}` expressions **before** the shell runs. If untrusted text (a PR title, branch name, issue body, comment) is interpolated directly into a `run:` step, attacker-controlled shell is executed. The interpolation happens at the expression layer, so `shell` quoting and metacharacter escaping in the script are irrelevant — the injected text is spliced in before the shell ever sees it.

Example sink: `run: echo "Building ${{ github.event.pull_request.title }}"`.

## 2. THE PRIVILEGE-ESCALATION PATTERNS

The severity comes from the *trigger*, not the payload:

- **`pull_request_target`** — runs with write permissions, secrets, and a checkout of the *base* repo by default, but the PR author is untrusted. Classic RCE + secret exfil + self-hosted runner compromise.
- **`workflow_run`** — triggers on completion of another workflow and can access its artifacts/secrets while the triggering actor is untrusted.
- **`issue_comment`** / **`issues`** — external users control the body and comment text.
- **`pull_request_target` + `actions/checkout` of `github.event.pull_request.head.sha`** — checks out attacker code *and* runs it with secrets.

Detection starts by finding which triggers a workflow uses:

```bash
grep -rnE 'pull_request_target|workflow_run|issue_comment|issues:|pull_request:' .github/workflows/
```

## 3. STATIC ANALYSIS — THE PRIMARY DETECTION

```bash
# List every untrusted-context interpolation inside run: blocks
grep -rnE '\$?\{\{\s*github\.event\.(pull_request|issue|comment|head_ref|discussion|review|workflow_run)' .github/workflows/ -A3 -B3

# Dedicated linters (CI-enforceable)
pip install zizmor actionlint
zizmor .github/workflows/          # flags template-injection and other GH Actions footguns
actionlint                        # syntax + expression misuse
```

`zizmor` is the strongest single tool here: it specifically detects template-injection sinks and dangerous checkout/permission combinations. Wire both into CI as a merge gate.

## 4. RUNTIME CONFIRMATION (CANARY, AUTHORIZED ONLY)

To *prove* execution of injected text (on a repo you control and have permission to test):

1. Add a harmless echo-based canary step that prints the interpolated value, OR
2. Use a **non-executing marker** in the untrusted field — e.g. set a PR title to `` `echo INJECTED-<nonce>` `` — and observe whether the marker is interpreted (a shell substitution prints the nonce in the job log) vs. treated as literal text.

Safe canary payload: `` `echo INJECTED-a1b2c3` `` (command substitution, read-only). It does not touch files or network. **Never** use a payload that writes to disk, exfiltrates a secret, or modifies the repo — testing this on production workflows risks exactly the compromise you're testing for. Restrict runtime canary tests to dedicated test repositories.

Detection-on-exploitation: alert on a workflow run whose step command line contains a string that came from the PR title, and on `pull_request_target` runs triggered by `fork` PRs.

## 5. EXPLOIT-STATE DETECTION

If a workflow was exploited, look for:
- Unusual `GITHUB_TOKEN` API activity during a run (e.g., token used to push, create releases, or modify settings) — check the run's token permissions and any subsequent repository changes by the token's job.
- Self-hosted runner egress right after a `pull_request_target` run (the runner may now be compromised).
- Secrets referenced in a run triggered by a fork.
- Modified workflow files or added steps appearing after a suspicious run.

```bash
gh run list --workflow=<name> --event=pull_request_target --json databaseId,headBranch,actor,conclusion
# Correlate fork PRs with runs that had secrets in scope.
```

## 6. REMEDIATION / HARDENING

- **Never interpolate untrusted context into `run:`.** Pass it through `env:` and read the env var in the shell:
  ```yaml
  - run: echo "Building $TITLE"
    env:
      TITLE: ${{ github.event.pull_request.title }}
  ```
- Use `pull_request` (not `pull_request_target`) for anything touching PR code; if you must use `_target`, **do not check out the PR head** and add an explicit `if:` guard on `github.event.pull_request.head.repo.fork == false`.
- Set a default `permissions: { contents: read }` at the workflow (or org) level and grant least privilege per job; avoid `write-all`.
- Pin third-party actions to a full commit SHA, not a tag.
- Protect `.github/workflows/**` with CODEOWNERS so changes require review; branch-protect the paths.
- Don't run untrusted PRs on self-hosted runners; use ephemeral, network-restricted runners if you must.
- Restrict `GITHUB_TOKEN` scope for fork PRs; never expose release/deploy secrets to fork-triggered workflows.
- Add `zizmor` + `actionlint` to CI and fail the build on template-injection findings.

## Sources
- https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
- https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- https://cwe.mitre.org/data/definitions/94.html (code injection in templated workflows)
- https://github.com/woodruffw/zizmor