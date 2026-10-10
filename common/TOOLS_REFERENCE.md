# Tools Reference — Bug Bounty

## WAF Detection & Fingerprinting
| Tool | Install | Purpose |
|------|---------|---------|
| wafw00f | `pip install wafw00f` | Detect WAF vendor |
| whatwaf | `pip install whatwaf` | Advanced WAF detection |
| waf-stressor | `git clone https://github.com/theghostshinobi/waf-stressor` | WAF stress testing |
| evilwaf | `git clone https://github.com/matrixleons/evilwaf` | MITM WAF bypass proxy |

## WAF Bypass Tools
| Tool | Install | Purpose |
|------|---------|---------|
| bypassburrito | `git clone https://github.com/Su1ph3r/bypassburrito` | LLM-powered WAF bypass generator |
| wafrift | `git clone https://github.com/santhsecurity/wafrift` | Programmable WAF-evasion engine |
| nowafplsV2 | Burp extension | WAF size-limit bypass via junk padding |
| WAFNinja | Burp extension | ML-powered WAF bypass (53 techniques) |
| bunnyburrow | `git clone https://github.com/vampiricbunny/bunnyburrow` | WAF bypass mapping + validation |

## Reconnaissance
| Tool | Install | Purpose |
|------|---------|---------|
| subfinder | `go install` | Passive subdomain enumeration |
| assetfinder | `go install` | Find subdomains from public sources |
| amass | `go install` | Deep subdomain discovery |
| chaos | `go install` | ProjectDiscovery Chaos |
| httpx | `go install` | HTTP probing toolkit |
| httprobe | `go install` | Live host detection |
| naabu | `go install` | Fast port scanner |
| nmap | `apt install nmap` | Service version + vuln scripts |
| gau | `go install` | Get all URLs (wayback + more) |
| waybackurls | `go install` | Wayback Machine URLs |
| katana | `go install` | Crawler |
| hakrawler | `go install` | Fast web crawler |
| gitleaks | `go install` | Git secret scanner |
| shodan | `pip install shodan` | Internet device search |
| censys | `pip install censys` | Certificate + infrastructure search |

## Scanning & Fuzzing
| Tool | Install | Purpose |
|------|---------|---------|
| nuclei | `go install` | Vulnerability scanner (7000+ templates) |
| ffuf | `go install` | Directory/parameter fuzzing |
| dalfox | `go install` | XSS scanner |
| sqlmap | `pip install sqlmap` | SQL injection automation |
| ghauri | `pip install ghauri` | Advanced SQLi (Go port) |
| interactsh-client | `go install` | OOB interaction listener |
| dnsx | `go install` | DNS toolkit |
| naabutonmap.py | ~/scripts/ | Convert naabu to nmap vuln scan |

## Custom Scripts (pre-installed ~/scripts/)
| Script | Purpose |
|--------|---------|
| urlfuzzer.sh | gau → uro → httpx → nuclei pipeline |
| alienvault.sh | Fetch URLs from AlienVault OTX |
| wayback.sh | Wayback URL fetcher |
| virustotal.sh | VirusTotal API scanner (3-key rotation) |
| urlscan.py | URLScan.io API client |
| dorking.py | Google dorking automation |
| naabutonmap.py | Naabu → Nmap vuln scanning |

## JavaScript Analysis
| Tool | Install | Purpose |
|------|---------|---------|
| SecretFinder | `pip install secretfinder` | Find secrets in JS files |
| jsluice | `go install` | JS static analysis |
| LinkFinder | `pip install linkfinder` | Endpoint discovery in JS |
| subjs | `go install` | JS file discovery |
| getJS | `go install` | Gather JS files from URLs |

## Bug Bounty Methodology Repos (GitHub)
| Repo | Stars | What It Contains |
|------|-------|-----------------|
| jhaddix/tbhm | 4357⭐ | The Bug Hunter's Methodology (full methodology) |
| su6osec/HuntBook | Latest | Comprehensive 2026 methodology |
| byoniq/BugBountyMethod | Practitioners | Tool-linked checklists per attack surface |
| amrelsagaei/Bug-Bounty-Hunting-Methodology-2025 | Reference | 2025 methodology guide |
| gl0bal01/intel-codex | All-in-one | SOP, methodologies, cheat sheets |
| shuvonsec/claude-bug-bounty | AI-integrated | Claude-integrated bug bounty workflow |
| vux06/BB-Methodology | Mega checklist | Recon → critical RCE + cloud exploits |
| The-XSS-Rat/SecurityTesting | Checklists | 2026 practical guide with WAF bypass section |

## Latest WAF Research (2026)
| Paper/Tool | Focus |
|------------|-------|
| BWAFSQLi (ACM 2026) | Adversarial SQLi WAF bypass framework |
| BypassBurrito v0.3.1 | LLM-powered WAF bypass generator |
| EvilWAF v1.0 | Transparent MITM Firewall bypass proxy |
| WAFRift v0.5 | Programmable WAF-evasion engine (evolutionary) |
| WAFNinja | BurpSuite ML-powered WAF bypass (53 techniques) |
| nowafplsV2 | WAF size-limit bypass via junk data injection |

## Quick Reference: Finding WAF Bypass
1. `wafw00f https://target.com` — identify WAF vendor
2. Test basic XSS/SQLi payload — confirm blocking pattern
3. Send payload through encoding layers (URL → double → unicode → entity)
4. Try comment injection, case randomization, whitespace tricks
5. Use bypassburrito / wafrift for automated mutation
6. Check for protocol downgrade (HTTP/2 → HTTP/1.0)
7. Try HPP, chunked encoding, body padding
8. If WAF has IP allowlist → use shodan/censys to find origin IP
9. Document which technique worked with exact payload
