# ARGUS.md — Argus Recon Toolkit (Aug 2026)

**Source:** https://github.com/jasonxtn/argus

## What it is
Python interactive CLI with 135 recon modules across 3 categories:
- Network & Infrastructure (DNS, ports, TLS, WHOIS, ASN, BGP...)
- Web Application Analysis (CMS, crawler, JS analyzer, CORS, params...)
- Security & Threat Intelligence (Shodan, VirusTotal, Censys, leaks...)

## Install (requires Python 3.10+ — system has 3.9, use venv)
```bash
git clone https://github.com/jasonxtn/argus.git ~/tools/argus
~/.local/bin/python3.11 -m venv ~/tools/argus/venv
~/tools/argus/venv/bin/pip install -r ~/tools/argus/requirements.txt
cd ~/tools/argus && ./venv/bin/python -m argus
# or: pip install argus-recon && argus
```

## CLI
```
argus> modules              # list all 135
argus> modules -d           # with details
argus> search ssl           # search modules by keyword
argus> use 42               # select module
argus> set target example.com
argus> set threads 20
argus> run
argus> runall infra         # run whole category
argus> runall web
argus> profile speed        # apply profile
argus> fav add 42           # favorite module
argus> runfav               # run favorites
argus> show api_status      # check API keys
argus> viewout / grepout    # cached output
```

## High-Value Modules (of 135)
| # | Module | Use |
|---|--------|-----|
| 118 | Subdomain Enumeration | passive subdomain discovery |
| 119 | Subdomain Takeover | dangling CNAME detection |
| 123 | Cloud Bucket Exposure | S3/GCS/Azure bucket checks |
| 126 | Git Repository Exposure | exposed .git |
| 124 | JWT Token Analyzer | JWT triage |
| 125 | Exposed API Endpoints | API surface discovery |
| 71 | CORS Misconfiguration Scanner | CORS audit |
| 73 | Hidden Parameter Discovery | param fuzzing |
| 80 | Virtual Host Fuzzer | vhost discovery |
| 129 | Open Redirect Finder | open redirect |
| 130 | Rate-Limit & WAF Bypass Test | rate limit / WAF |
| 93 | GraphQL Introspection Probe | GraphQL schema |
| 90 | API Schema Grabber | OpenAPI discovery |
| 105 | Data Leak Detection | data exposure |
| 106 | Exposed Environment Files | .env leaks |
| 115 | Shodan Reconnaissance | Shodan intel |
| 103 | Censys Reconnaissance | Censys intel |
| 120 | VirusTotal Scan | VT intel |
| 121 | CT Log Query | cert transparency |
| 122 | Breached Credentials Lookup | HIBP |

## API Keys (env vars or config/settings.py)
```
VIRUSTOTAL_API_KEY, SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET,
GOOGLE_API_KEY, HIBP_API_KEY
```

## Pipeline Placement
```
1. chaos/subfinder/crt.sh → subs.txt
2. httpx -l subs.txt -ip → ip.txt
3. naabu/nmap on origin IPs
4. nuclei on everything
5. Argus runall infra + web   → broad coverage sweep
```

## Notes
- Argus is a broad aggregator — good for coverage, not depth.
- Use it to catch things the main pipeline misses (takeover, buckets, .env).
- Interactive CLI — scripted use is limited; run per-target.