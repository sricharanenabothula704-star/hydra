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

**THE 7-HEADED AI BUG BOUNTY SYSTEM · 928 SKILLS · FULL METHODOLOGY · ONE-COMMAND SETUP**

👤 **Author:** `sricharan996`

<br>

<a href="https://sricharan996.github.io"><img src="https://img.shields.io/badge/🌐_WEBSITE-LIVE-00E5FF?style=for-the-badge&logo=githubpages&logoColor=white"></a>
<a href="#-quickstart"><img src="https://img.shields.io/badge/SETUP-ONE%20COMMAND-00FF41?style=for-the-badge"></a>
<a href="#-the-agent-pipeline"><img src="https://img.shields.io/badge/AGENTS-7-FF003C?style=for-the-badge"></a>
<a href="#skills"><img src="https://img.shields.io/badge/SKILL%20MODULES-989-9D00FF?style=for-the-badge"></a>
<a href="#-methodology-library"><img src="https://img.shields.io/badge/METHODOLOGY%20DOCS-26-00E5FF?style=for-the-badge"></a>
<a href="#scripts"><img src="https://img.shields.io/badge/AUTOMATION-16%20SCRIPTS-FF6D00?style=for-the-badge"></a>
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
| 🗂️ Tracked files | **246+** |
| 🤖 AI agents | **7** |
| 🧩 Skill modules | **989** |
| 📖 Methodology playbooks | **26** |
| ⚙️ Automation tools | **26** |
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
## 🧩 Skill Modules — 928

Machine-indexed in [`skills/index.json`](skills/index.json) so agents route programmatically:

| Category | Count | Highlights |
|----------|:-----:|------------|
| 🌐 Web exploitation | **38** | XSS, SQLi, SSRF, SSTI (+ error-based), request smuggling (+ modern desync), GraphQL, prototype pollution, ORM filter injection |
| 🖥️ Platform attacks | **16** | Linux/Windows/macOS privesc, Active Directory (kerberos, ACL abuse, AD CS), k8s, containers |
| ⚙️ Binary exploitation | **11** | Heap, ROP, format string, kernel, V8, sandbox escapes |
| 🔍 Recon | **9** | Subdomain takeover, DNS rebinding, source-control leaks, JS analysis |
| 🔐 Crypto | **6** | RSA, lattice, symmetric, hash attacks |
| 📱 Mobile | **3** | Android, iOS, SSL pinning bypass |
| 🤖 AI security | **2** | LLM prompt injection, AI/ML supply chain |

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
git clone https://github.com/sricharan996/hydra.git
cd hydra && bash setup.sh        # asks handle + email, installs everything
source ~/.bashrc                 # pick up freshly installed binaries
export OPENROUTER_API_KEY=sk-or-...   # any OpenAI-compatible provider
# bash install-tools.sh          # optional: recon toolchain
```

**2 — Inside the opencode session** (run `opencode` first, then type these):

```
/hunt example.com                # ONLY on authorized targets!
/verify <finding-file>
/report <verified-finding>
```

## 🛡️ Safety Model

- **CI guardrails on every push**: secret-pattern scanning, shell/python syntax checks, agent validation — nobody can leak secrets into this repo, including future-you
- **Verifier agent kills false positives** before they reach a triage queue
- **`.gitignore` blocks recon output** and secret-shaped files by design
- Findings stay local under `~/recon_reports/` — never committed

## 📁 Repository Layout

<details>
<summary><b>Full structure</b></summary>

```
├── agents/            7 agent definitions (context-rich prompts + protocols)
├── skills/            931 security skill modules + index.json
├── common/            26 methodology playbooks
├── docs/              strategy library (planning, Tor, case study...)
├── templates/         BugBase report template
├── scripts/           16 automation tools
├── .github/workflows/ CI security guardrails
├── setup.sh           one-command installer
└── install-tools.sh   recon toolchain installer
```

</details>

## 🔗 Related

- [bug-bounty-research](https://github.com/sricharan996/bug-bounty-research) — companion research workspace mirror

## 📜 Credits & License

- Built on [opencode](https://opencode.ai)
- Tooling by ProjectDiscovery (subfinder, httpx, naabu, nuclei), ffuf, dalfox
- Licensed [MIT](LICENSE) — but you own everything you do with it. **Hack ethically.**

---

<div align="center">

**⭐ Star this repo if it helps you find your next critical!**

</div>
