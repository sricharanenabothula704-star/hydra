# Deterministic enforcement

HYDRA separates **reasoning** from **enforcement**. The model proposes; a set
of deterministic, model-independent gates decides. No gate reads model output
to decide whether to allow an action, and no gate can be talked out of a
decision by a prompt.

## Why this matters

Frontier models are poor judges of report validity. In a published study of
9,942 disclosed HackerOne reports, GPT-5 judging report validity reached 0.91
recall on valid reports but **0.28 recall on invalid ones** — meaning roughly
72% of invalid reports were accepted as valid. In the same work, appending
vendor scope text as prose made classification *worse* (macro-F1 0.583 →
0.535); only structured retrieval over real prior rejections helped
(0.885 accuracy, 0.856 invalid recall).

Those numbers are the argument for this module set. A gate that is a language
model is not a gate.

See: *From Reviewers' Lens* — https://arxiv.org/abs/2511.18608

## The gates

| Gate | Module | Decides |
|---|---|---|
| Scope | `core/scope_policy.py` | Is this host authorized? |
| Endpoint protection | `core/protected_endpoints.py` | Is this path safe to touch? |
| Validation evidence | `core/validation_evidence.py` | Is this finding confirmed, or a lead? |
| Report contract | `core/report_contract.py` | Would a triager close this as N/A? |
| Audit trail | `core/audit_trail.py` | What did we actually do, and when? |

Each gate is callable without a model present:

```bash
hydra guard https://example.com/logout      # explain both gates, contact nothing
hydra gates                                 # run the offline evaluation
hydra audit                                 # summarize recorded decisions
hydra audit --verify                        # detect tampering
```

### Scope

Host allowlist with canonical DNS-label matching. Exact entries cover the
apex and its subdomains; `*.example.com` covers children only. Suffix
collisions (`evil-example.com`), lookalike hosts (`example.com.attacker.net`)
and URL userinfo tricks are rejected. Missing or empty allowlists fail
closed.

### Endpoint protection

Scope answers "is this host authorized?". It does not answer "is this path
safe?". A fully in-scope host still contains paths that destroy the account
you are testing with:

| Category | Example | Action |
|---|---|---|
| Session destruction | `/logout`, `/invalidate-sessions` | block |
| Account destruction | `/delete-account`, `/account/delete` | block |
| Credential mutation | `/reset-password`, `/change-email` | block |
| MFA / OTP | `/2fa/disable`, `/reset-otp` | block / auth-only |
| Auth entry points | `/login`, `/signup` | auth-only |

Rules are literal path patterns anchored to the path start, so neither a
query string (`/search?next=/logout`) nor duplicate slashes (`/api//logout`)
can bypass them. This closes a failure mode that open-source agents in this
space do not handle: an automated run logging itself out mid-assessment or
tricking its own test account into lockout.

### Validation evidence

Findings carry typed evidence, and the weakest link decides the verdict:

* `deterministic` — a programmatic oracle observed the effect (a headless
  browser confirmed script execution; a timing oracle measured a latency
  delta). Re-running reproduces it.
* `heuristic` — indirect evidence: response differentials, configuration
  review. Sufficient to confirm, flagged as such.
* `unverified` — no independent evidence. A lead. Never reported as confirmed.

This converts "false positive rate" from a global vanity metric into a
per-class property with a named mechanism — the approach used by the leading
commercial systems, where classes backed by a non-model validator are stated
to carry no false positives and agent-validated classes may.

Human confirmation remains mandatory regardless of evidence strength, because
platform policy requires a person to confirm potential vulnerabilities before
submission.

### Report contract

Mechanical pre-submission linting against published rejection criteria:
missing proof of concept, missing demonstrated impact, no reproducible
command, video-only evidence, credentials embedded in a URL, unassigned
severity. Critical severity produces a warning, since repeated inflated
severity is itself a policy violation.

### Audit trail

Append-only JSONL, one record per decision, content-hashed per record.
`hydra audit --verify` detects post-hoc edits. Answers the first question any
buyer's counsel asks: what did this agent actually do at 3:47 AM?

## Measured behaviour

```bash
python -m core.evaluation_harness
```

```
HYDRA deterministic-gate evaluation (offline, no model, no network)
========================================================================
scope      11/11  (100.0%)
endpoint   19/19  (100.0%)
evidence    7/7   (100.0%)
report      6/6   (100.0%)
========================================================================
OVERALL     43/43  (100.0%)
```

The suite is deterministic — no clock, no randomness, no network — so the
numbers reproduce on any machine. It covers the collision cases a naive
substring matcher fails (`evil-example.com`, `example.com.attacker.net`,
userinfo tricks), the destructive-path matrix including bypass attempts, the
evidence discipline, and report-contract enforcement.

**What this does not measure.** It does not measure vulnerability-discovery
recall or live-target precision; that requires authorized live targets and a
triage oracle. Public security-agent benchmarks measure recall almost
exclusively, and their own maintainers note public sets saturate — XBOW's
retired its CTF benchmark at roughly 100% because the underlying
vulnerabilities entered model training. Treat any accuracy number here as
covering the gates only.

## Argv-level tool guard — built, NOT active

`core/tool_guard.py` enforces scope on the **argument vector of the tool
itself**, rather than trusting the caller to ask first. An audit found 21
network-touching helper scripts that never consulted the scope gate, and inside
an agent session scope was a prompt instruction rather than a control. Moving
the check into the invocation means it survives a careless script, a new
script nobody audited, or an agent calling `sqlmap` directly.

**It is not wired to `PATH`.** The `bin/guard-bin/` shims do not exist, so
nothing is intercepted at runtime. The module is shipped unexposed, on
purpose, until its parsing accuracy has been reviewed by someone who did not
write the parser.

What it does, when enabled:

* **Fails closed.** No identifiable target in a non-informational invocation is
  a *denial*, not a pass — an argv parser that cannot recognise a target must
  not become a bypass.
* Reads targets out of request files (`sqlmap -r`), tool configs (`nuclei -c`)
  and list files, and refuses an unreadable or hostless list rather than
  running blind.
* Checks both ends of a connection override (`curl --resolve host:port:addr`),
  and treats the proxy host as a target in its own right.
* Denies cloud instance metadata (`169.254.169.254`), private, loopback and
  link-local literals, and any IP or CIDR not explicitly allowlisted.
* Refuses URL userinfo outright, because `http://evil.com\@example.com` is host
  `example.com` to a strict parser and `evil.com` to a lenient one.

### Why it is a guardrail and not a boundary

It covers tools launched through the shimmed `PATH`. It does **not** cover
`/usr/bin/nmap` invoked by absolute path, `python -c "requests.get(...)"`, or a
raw socket. Redirects are the clearest irreducible gap: a host reached by
following a redirect never appears in any argument vector, at any parser.

Treat it as a large reduction in *accidental* out-of-scope work, and as
incomplete. The control that actually survives a compromised agent is the
egress proxy listed under Known limits below.

Tests: `tests/test_tool_guard.py` (42 cases, including a fuzz pass asserting
the guard never raises and never permits an explicitly out-of-scope host).
Each case documents a bug that was live during development.

## Known limits

* **No egress proxy.** A determined agent with shell access can bypass a
  library-level gate by using another tool. Network-layer enforcement (DNS
  or proxy chokepoint) is the only control that survives a fully compromised
  agent, and is not implemented. This is the single largest gap.
* **Argv guard is not active** (above) and would not be a boundary even if it
  were.
* No independent guardian reviewing proposed actions outside the agent's own
  reasoning chain.
* Some standalone helper scripts in `scripts/` do not call these gates; they
  require separate review before use.
* Endpoint rules are English-path heuristics and will not cover applications
  with non-obvious or localized routes. They default to allowing anything not
  matched, so they reduce self-inflicted damage rather than proving safety.
