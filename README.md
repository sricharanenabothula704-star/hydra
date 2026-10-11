<div align="center">

```
██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ 
██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗
███████║ ╚████╔╝ ██║  ██║██████╔╝███████║
██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║
██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║
╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

# 🐉 HYDRA

**THE 7-HEADED AI BUG BOUNTY SYSTEM · 1,179 SKILLS · FULL METHODOLOGY · ONE-COMMAND SETUP**

👤 **Author:** `sricharanenabothula704-star`

<br>

<a href="https://sricharanenabothula704-star.github.io"><img src="https://img.shields.io/badge/🌐_WEBSITE-LIVE-00E5FF?style=for-the-badge&logo=githubpages&logoColor=white"></a>
<a href="#-quickstart"><img src="https://img.shields.io/badge/SETUP-ONE%20COMMAND-00FF41?style=for-the-badge"></a>
<a href="#-the-agent-pipeline"><img src="https://img.shields.io/badge/AGENTS-7-FF003C?style=for-the-badge"></a>
<a href="#skills"><img src="https://img.shields.io/badge/SKILL%20MODULES-1179-9D00FF?style=for-the-badge"></a>
<a href="#-methodology-library"><img src="https://img.shields.io/badge/METHODOLOGY%20DOCS-27-00E5FF?style=for-the-badge"></a>
<a href="#scripts"><img src="https://img.shields.io/badge/AUTOMATION-35%20SCRIPTS-FF6D00?style=for-the-badge"></a>
<a href="#-safety-model"><img src="https://img.shields.io/badge/CI%20GUARDRAILS-ACTIVE-00FF41?style=for-the-badge&logo=githubactions&logoColor=white"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-FFD500?style=for-the-badge"></a>

<br>

```
┌────────────────────────────────────────────────────────────────────────────┐
│  Seven heads. One hunt. HYDRA is an AI-agent bug-bounty framework          │
│  built on opencode — passive recon to submission-ready reports.            │
│  Sanitized, credential-free, CI-guarded.                                   │
│                                                                            │
│  ⚠️  AUTHORIZED TESTING ONLY — see DISCLAIMER.md                           │
└────────────────────────────────────────────────────────────────────────────┘
```

</div>

---

## 🧭 Navigation

| # | Section | # | Section |
|---|---------|---|---------|
| 01 | [Stats](#-stats) | 06 | [Methodology Library](#-methodology-library) |
| 02 | [The Agent Pipeline](#-the-agent-pipeline) | 07 | [Quickstart](#-quickstart) |
| 03 | [Skill Modules](#skills) | 08 | [Safety Model](#-safety-model) |
| 04 | [Automation Scripts](#scripts) | 09 | [Repository Layout](#-repository-layout) |
| 05 | [Strategy Docs](#-strategy-docs) | 10 | [Credits & License](#-credits--license) |

---

## 📊 Stats

| Metric | Count |
|--------|:-----:|
| 🗂️ Tracked files | **4,856** |
| 🤖 AI agents | **7** |
| 🧩 Skill modules | **1,179** |
| 📖 Methodology playbooks | **27** |
| ⚙️ Automation tools | **35** |
| 🗺️ Strategy documents | **8** |

---

## 🤖 The Agent Pipeline

```
                 ┌─────────────────────────────────────────────┐
                 │                opencode CLI                  │
                 └─────────────────────────────────────────────┘
   /hunt ──► HUNTER ──┐                    Core pipeline:
                      │                    CHAOS → HTTPX → NAABU
   /verify ─► VERIFIER├── shared memory    → NMAP → NUCLEI → FFUF
                      │   (~/.config/opencode/
   /report ─► REPORTER┘     agent_memory/)
                                 ▲        │
                       DEBUG ────┘        └── PLAN / AUDITOR / RECON
```

| Agent | Role | Superpower |
|-------|------|-----------|
| 🔴 **HUNTER** | Full recon + exploitation | WAF bypass arsenal, continuous probing cycles, finding hashing |
| 🟠 **VERIFIER** | Zero-false-positive gate | 3-request reproducibility, response diffing, CVSS calibration |
| 🔵 **REPORTER** | Submission-ready reports | Triager psychology, ≤120-char titles, working curl PoCs |
| 🟢 **PLAN** | Strategic attack planning | Internet research → P0–P3 prioritized vectors |
| 🟣 **DEBUG** | Self-improvement engine | Cross-agent memory propagation, mistake prevention rules |
| 🟡 **AUDITOR** | Source-level code audit | 6-phase methodology, trust-boundary mapping, evidence standards |
| 🩳 **RECON** | Fast attack-surface mapper | Passive-first, CDN tagging, structured handoff contract |

Every agent ships with mission context, decision frameworks and output contracts — not just command dumps.

### Inside each agent file (`agents/<name>.md`)

Each of the seven files is a complete operating manual, not a prompt stub:

| File | Mission | Built-in discipline |
|------|---------|---------------------|
| `hunter.md` (559 ln) | Recon-to-exploitation pipeline execution | Standing decision table (403→bypass, WAF→vendor bypass, silence→change layer); findings hashed & saved instantly; scope-gated |
| `verifier.md` (149 ln) | Destroy false positives before triage does | 3-request reproducibility, baseline-vs-exploit diffing, ≥80% confidence bar, calibration psychology |
| `reporter.md` (255 ln) | Submission-ready writeups | Triager-psychology rules, ≤120-char titles, working curl PoCs, honest severities |
| `plan.md` (149 ln) | Pre-engagement strategy | Web research → P0–P3 vector prioritization → success criteria → pivot conditions |
| `auditor.md` (115 ln) | Source-level code review | 6 phases with rationale; trust-boundary mapping; every finding needs location+reachability+PoC |
| `recon.md` (97 ln) | Passive-first surface mapping | Scope gate before packet one; saturation detection; structured handoff contract; tool fallback chains |
| `debug.md` (167 ln) | Cross-agent self-improvement | Mistake→fix→prevention-rule logging; memory propagation; parallel web-search self-rescue protocol |

All seven also carry: **TODO-list discipline** (plan before acting, live status updates) and the **Self-Rescue Protocol** (parallel websearch + primary-source fetch + 2-source cross-verification when stuck).

<a id="skills"></a>
## 🧩 Skill Modules — 1,179

Machine-indexed in [`skills/index.json`](skills/index.json) so agents route programmatically:

| Category | Count | Highlights |
|----------|:-----:|------------|
| 🌐 Web exploitation | **284** | XSS, SQLi, SSRF, SSTI, GraphQL, API authorization, and web-specific CVE playbooks |
| 🛡️ Forensics & defense | **167** | Incident response, malware analysis, threat hunting, and detection engineering |
| 🖥️ Platform attacks | **69** | Linux/Windows/macOS, Active Directory, cloud, containers, and platform CVEs |
| ⚙️ Binary exploitation | **14** | Heap, ROP, format strings, memory safety, and binary analysis |
| 🔍 Recon | **17** | Subdomain and DNS research, source-control exposure, and JavaScript analysis |
| 🔐 Crypto | **18** | TLS, key management, cryptographic attacks, and implementation reviews |
| 📱 Mobile | **11** | Android, iOS, mobile APIs, and application security |
| 🤖 AI security | **10** | LLM, prompt injection, agentic systems, and ML supply chain |
| 🧰 Other security skills | **389** | Specialized security assessment and defensive engineering guides |
| 🧪 CVE & specialized playbooks | **200** | CVE-, CWE-, framework-, and scenario-specific guides |

**2025–2026 state of the art included:** Next.js middleware bypass (CVE-2025-29927) · XS-Leaks (ETag length oracle) · CSS exfiltration · web timing attacks · 0.CL desync · error-based blind SSTI.

<a id="scripts"></a>

### MITRE ATT&CK coverage

| Tactic | ID | Skills | | Tactic | ID | Skills |
|--------|----|-------:|-|--------|----|-------:|
| Reconnaissance | TA0043 | 103 | | Credential Access | TA0006 | 202 |
| Resource Development | TA0042 | 22 | | Discovery | TA0007 | 237 |
| Initial Access | TA0001 | 467 | | Lateral Movement | TA0008 | 68 |
| Execution | TA0002 | 350 | | Collection | TA0009 | 172 |
| Persistence | TA0003 | 444 | | Command and Control | TA0011 | 123 |
| Privilege Escalation | TA0004 | 464 | | Exfiltration | TA0010 | 82 |
| Stealth | TA0005 | 442 | | Impact | TA0040 | 50 |
| Defense Impairment | TA0112 | 92 | | | | |

### What's inside — 29 security domains

| Domain | Skills | Key capabilities |
|--------|-------:|------------------|
| Cloud Security | 66 | AWS, Azure, GCP hardening · CSPM · cloud attack emulation · cloud forensics |
| Threat Hunting | 58 | Hypothesis-driven hunts · LOTL detection · EVTX hunting · fleet hunting |
| Threat Intelligence | 52 | STIX/TAXII · MISP · OpenCTI · feed integration · actor profiling |
| Network Security | 43 | IDS/IPS · firewall rules · VLAN segmentation · traffic analysis |
| Web Application Security | 42 | OWASP Top 10 · SQLi · XSS · SSRF · deserialization |
| Digital Forensics | 41 | Disk imaging · memory forensics · Hayabusa/KAPE/Plaso timelines |
| Malware Analysis | 39 | Static/dynamic analysis · reverse engineering · sandboxing |
| Identity & Access Management | 37 | Entra ID/ROADtools · device-code phishing · PAM · zero trust identity |
| SOC Operations | 35 | Playbooks · escalation workflows · Graph-log detection · tabletop exercises |
| Red Teaming | 33 | ADCS/Certipy · BloodHound CE · Sliver/Havoc C2 · NTLM relay |
| Container Security | 33 | K8s RBAC · image scanning · Falco · container escape |
| Security Operations | 28 | SIEM correlation · log analysis · alert triage |
| OT/ICS Security | 28 | Modbus · DNP3 · IEC 62443 · historian defense · SCADA |
| API Security | 28 | GraphQL · REST · OWASP API Top 10 · WAF bypass |
| Incident Response | 26 | Breach containment · ransomware response · IR playbooks |
| Vulnerability Management | 25 | Nessus · scanning workflows · patch prioritization · CVSS |
| Penetration Testing | 21 | Network · web · cloud · mobile · NetExec lateral movement |
| DevSecOps | 18 | CI/CD security · Trivy IaC/image scanning · code signing |
| Zero Trust Architecture | 17 | BeyondCorp · CISA maturity model · microsegmentation |
| Endpoint Security | 17 | EDR · LOTL detection · fileless malware · persistence hunting |
| Cryptography | 16 | TLS · Ed25519 · post-quantum migration · key management |
| Phishing Defense | 15 | Email authentication · BEC detection · phishing IR |
| AI Security | 14 | LLM red-teaming (garak/PyRIT) · prompt injection · MCP/agentic security · guardrails |
| Mobile Security | 13 | Android/iOS analysis · mobile pentesting · MDM forensics |
| Ransomware Defense | 13 | Precursor detection · response · recovery · encryption analysis |
| Compliance & Governance | 9 | NIST 800-30/RMF · CMMC · HIPAA · TPRM · CIS benchmarks |
| Supply Chain Security | 8 | SBOMs · dependency confusion · malicious-package triage · SLSA/Sigstore |
| Deception Technology | 6 | Honeytokens · canarytokens · breach detection |
| Hardware & Firmware Security | 4 | CHIPSEC/UEFI audit · Secure Boot bypass · TPM attestation · bootkit hunting |

### ♾️ Loop Mode — autonomous continuous hunting

```bash
./scripts/hydra_loop.sh doctor        # pre-flight: audits every stop-condition
tmux new -s hydra                     # survives disconnects
./scripts/hydra_loop.sh targets.txt 40
```

Endless cycles of `/hunt` across your authorized target rotation. Built around the six ways agent loops die — context exhaustion (fresh process per cycle, state on disk), "done" declarations (continuous-mode prompt), rate limits (auto-backoff), crashes (watchdog restart), diminishing returns (target+methodology rotation), and disconnects (tmux). Scope gate runs before every cycle; `doctor` audits all of it.

### The core library — original 111 hand-built modules

The hand-crafted foundation beneath the catalog: **38** web exploitation (XSS→smuggling→desync), **16** platform attacks (AD/kerberos/AD CS, privesc), **11** binary exploitation (heap/ROP/kernel/V8), **9** recon, **6** crypto, **3** mobile, **2** AI security — plus the WAF bypass database, error-based SSTI & modern-desync deep-dives, ORM filter injection, XS-Leaks and Next.js attack playbooks.

Curated AI-security reading list: [`docs/AI_SECURITY_RESOURCES.md`](docs/AI_SECURITY_RESOURCES.md).

## ⚙️ Automation Scripts

| Script | Purpose |
|--------|---------|
| `urlfuzzer.sh` | gau → uro → httpx → nuclei passive fuzzing pipeline |
| `naabutonmap.py` | Naabu results → deep Nmap vuln scanning |
| `coordinate.py` + `coordination_server.py` | Multi-agent orchestration |
| `verify_agent.sh` / `report_agent.sh` | Standalone verification & report generation |
| `nextjs_chunk_extractor.sh` | Route/action extraction from Next.js builds |
| `virustotal.sh` / `urlscan.py` / `alienvault.sh` / `wayback.sh` | OSINT collectors (env-var API keys) |
| `dorking.py` / `punycode_gen.py` / `sast_fuzzer.py` | Dork automation, IDN homoglyphs, SAST fuzzing |
| `recon_pipeline.sh` | Full passive→active recon chain in one command |
| `js_secret_hunt.sh` | Harvest JS bundles, grep 12 secret-pattern families |
| `cors_probe.sh` | Origin-reflection / null / suffix-bypass CORS audit |
| `actuator_probe.sh` | Spring actuator discovery + header bypass attempts |
| `takeover_probe.sh` | Dangling CNAME + takeover fingerprint matching |
| `backup_brute.sh` | Backup/config extension fuzzing via ffuf |
| `wayback_diff.sh` | Surface-diff: NEW endpoints since last snapshot |
| `nuclei_runner.sh` | Tagged nuclei pass with rate control + triage summary |

## 🗺️ Strategy Docs

Strategic attack planning · Recon execution methodology · OSINT targets reference · Tor anonymity setup · Real-world recon case study — all in [`docs/`](docs/).

## 🚀 Quickstart

**1 — In your shell** (install + configure):

```bash
git clone https://github.com/sricharanenabothula704-star/hydra.git
cd hydra
bash setup.sh --handle YOUR_HANDLE --email you@example.com
hydra doctor                        # verify config and scope file
# bash install-tools.sh          # optional: recon toolchain
```

HYDRA leaves the model unset so OpenCode manages model selection. In the TUI,
use `/connect` to authenticate with a provider and `/models` to inspect or change
models. OpenCode Zen is one option (it may require an account/API key and paid
credits); OpenRouter remains optional, not a setup requirement.

If OpenCode is not installed, rerun setup with `--install-opencode` after
reviewing and approving the official installer. If an OpenCode config already
exists, setup backs it up and asks before replacing it. For an AI-assisted,
step-by-step setup, copy [`docs/AI_SETUP_PROMPT.md`](docs/AI_SETUP_PROMPT.md)
into your coding agent.

For the optional browser MCP, use the `/playwright-setup` OpenCode command or
the second, dedicated prompt in
[`docs/AI_PLAYWRIGHT_MCP_SETUP_PROMPT.md`](docs/AI_PLAYWRIGHT_MCP_SETUP_PROMPT.md).
The `/browser-check` command is for ordinary, scope-checked browser validation;
neither command enables bot-detection evasion.

Setup also connects the attributed, MIT-licensed
[BugBounty MCP Server](https://github.com/gokulapap/bugbounty-mcp-server) to
OpenCode over local stdio. It is pinned and fail-closed: `SAFE_MODE=true`,
empty `ALLOWED_TARGETS`, and optional external scanners disabled. Read
[`docs/BUGBOUNTY_MCP.md`](docs/BUGBOUNTY_MCP.md) before configuring any authorized
network scope; this MCP server's scope setting is separate from HYDRA's list.

Add only written-authorized hosts to `~/.config/opencode/SCOPE_ALLOWLIST.txt`.
For one safe request, run `hydra scan https://your-authorized-host` (HTTP
security headers only). For the agent workflow, run `opencode` and then type:

```
/hunt example.com                # ONLY on authorized targets!
/verify <finding-file>
/report <verified-finding>
```

The installed CLI also provides one-request HTTP-header checks and scoped
OpenCode runs:

```bash
hydra doctor
hydra scan https://your-authorized-host
hydra hunt https://your-authorized-host
hydra pipeline list
hydra pipeline run recon --target https://your-authorized-host --execute
```

`pipeline run` and `chains run` show a plan by default. `--execute` is required
to hand it to OpenCode, and the target must pass the local scope allowlist.

### Optional browser validation (Playwright MCP)

The Playwright MCP entry is disabled by default. It can help inspect rendered
pages and validate client-side behavior on local or explicitly authorized
targets; it does **not** bypass bot detection or enforce HYDRA's scope
allowlist. To enable and use it safely, follow
[`docs/PLAYWRIGHT_MCP.md`](docs/PLAYWRIGHT_MCP.md). Stop if a site presents a
CAPTCHA, bot challenge, rate limit, or access denial.

## 🔒 Supply-Chain Vetting

A 1,179-module skill library is an attack surface, not only an asset. Research
on 31,132 public agent skills found **26.1% contained vulnerabilities and 5.2%
showed likely malicious intent** — skills execute with implicit trust.

HYDRA vets its own corpus on every push:

```bash
python scripts/skill_supply_chain_scan.py --fail-on critical
```

First run against HYDRA returned **20 `critical` findings — almost all false
positives**: a CI scanner's `if "curl" in x and "| sh" in x:` predicate is a
*detection*, not a vulnerability. A pattern scanner cannot tell a tool that
hunts a dangerous construct from a tool that is one. Rather than tune the
rules into uselessness or hide the hits, suppressions are explicit, scoped to
one file plus one rule, and each carries a written reason. Two tests fail the
build if a suppression goes stale.

The largest genuine finding: **166 instances of disabled TLS verification**
(`verify=False`) in shipped modules. Tracked, not suppressed.

Method, numbers, and limits: **[docs/SKILL_SUPPLY_CHAIN.md](docs/SKILL_SUPPLY_CHAIN.md)**

## 🛡️ Deterministic Enforcement

**The model proposes. Deterministic code decides.** No gate in HYDRA reads
model output to decide whether to allow an action, and none can be argued
out of a decision by a prompt.

This matters because frontier models are measurably poor judges of validity.
In a study of 9,942 disclosed HackerOne reports, GPT-5 reached 0.91 recall on
valid reports but **0.28 on invalid ones** — accepting roughly 72% of invalid
reports. In the same work, appending vendor scope text as prose made
classification *worse*; only structured retrieval over real prior rejections
helped. A gate that is a language model is not a gate.
([arXiv:2511.18608](https://arxiv.org/abs/2511.18608))

| Gate | Decides | Module |
|---|---|---|
| **Scope** | Is this host authorized? | `core/scope_policy.py` |
| **Endpoint protection** | Is this path safe to touch? | `core/protected_endpoints.py` |
| **Validation evidence** | Confirmed finding, or lead? | `core/validation_evidence.py` |
| **Report contract** | Would a triager close this as N/A? | `core/report_contract.py` |
| **Audit trail** | What did we do, and when? | `core/audit_trail.py` |

Endpoint protection is the part most agents in this space lack. Scope
allowlisting says a host is authorized; it says nothing about whether
`/delete-account`, `/logout`, or `/reset-password` will destroy the account
you are testing with. HYDRA blocks those paths by literal pattern, anchored
so a query string or duplicate slash cannot smuggle a match.

```bash
hydra guard https://example.com/logout   # explain both gates, contact nothing
hydra gates                              # run the offline evaluation
hydra audit --verify                     # detect tampering
```

Measured, not asserted — deterministic, offline, reproducible anywhere:

```
scope      11/11  (100.0%)
endpoint   19/19  (100.0%)
evidence    7/7   (100.0%)
report      6/6   (100.0%)
OVERALL     43/43  (100.0%)
```

Full rationale, measured behaviour, and known limits: **[docs/ENFORCEMENT.md](docs/ENFORCEMENT.md)**

## 🛡️ Safety Model

- **CI checks on every push**: secret-pattern scanning, shell/Python syntax checks, index consistency, and agent validation; these reduce risk but cannot guarantee that every secret or defect is caught
- **Verifier reviews candidate findings** with heuristic checks; humans must reproduce findings and review evidence before reporting
- **`.gitignore` blocks recon output** and secret-shaped files by design
- Findings are stored locally by default under `~/recon_reports/`; optional integrations may transmit data, so inspect their configuration before enabling them

## 📁 Repository Layout

<details>
<summary><b>Full structure</b></summary>

```
├── agents/            7 agent definitions (context-rich prompts + protocols)
├── skills/            1,179 security skill modules + index.json
├── common/            27 methodology playbooks
├── docs/              strategy library (planning, Tor, case study...)
├── templates/         BugBase report template
├── scripts/           35 automation tools
├── .github/workflows/ CI security guardrails
├── setup.sh           one-command installer
└── install-tools.sh   recon toolchain installer
```

</details>

## 🔗 Related

- [HYDRA knowledge base](https://github.com/sricharanenabothula704-star/hydra/tree/main/knowledge_base) — searchable security research notes

## 📜 Credits & License

- Built on [opencode](https://opencode.ai)
- Tooling by ProjectDiscovery (subfinder, httpx, naabu, nuclei), ffuf, dalfox
- Licensed [MIT](LICENSE) — but you own everything you do with it. **Hack ethically.**

---

<div align="center">

**⭐ Star this repo if it helps you find your next critical!**

</div>
