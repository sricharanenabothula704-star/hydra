# Strategic Bug Bounty Attack Plan
## Date: July 5, 2026
## Author: PLAN Agent
## Status: Research Complete — Ready for Execution

---

# EXECUTIVE SUMMARY

This plan covers **three tiers** of bug bounty targets:

1. **Tier 1 (BugBase Programs)** — Indian platforms paying in both cash (Bounty) and non-cash (Swags/Vouchers)
2. **Tier 2 (Global Top Payers)** — HackerOne, Bugcrowd, Immunefi high-reward programs
- Coupon-code testing guidance removed (program-specific)

---

# PHASE 0: TARGET RECONNAISSANCE RESULTS

## BugBase (bugbase.ai) — Platform Recon

| Attribute | Detail |
|-----------|--------|
| HQ | San Francisco, CA + New Delhi, India + Singapore |
| Founders | Dhruva Goyal (CEO), Kathan Desai |
| Funding | Pre-Seed |
| Employees | 11-50 |
| Tech | Continuous Vulnerability Assessment Platform |
| Certifications | SOC2, ISO 27001 |
| Researcher Community Size | Growing (Indian-focused) |
| Apollo Program | Private elite community, bounties up to $3,000 |
| CTF Competitions | CyberSeige 2.0 (up to ₹50,000 INR) |

### BugBase Programs Directory — Full Breakdown

| Program | Type | Reward Type | Bounty Range | Managed? |
|---------|------|-------------|--------------|----------|
| **BugBase** (own) | Bug Bounty | Bounty Thanks | $100-$500 Critical | Managed |
- Coupon-code testing guidance removed (program-specific)
| **Needl.Ai** | VDP | Thanks | Non-monetary (recognition) | Managed |
| **Tata Motors** | VDP | Thanks | Non-monetary | Upcoming |
| **Cloud Software Group** | Bug Bounty | Bounty Thanks | TBD | Upcoming |
| **Fintech-A** | Bug Bounty | Bounty Thanks | **$100-$3,000** | Self-managed |
| **Airmeet** | VDP | **Swags Thanks** | Swag items | Self-managed |
| **Shelfmerch VDP** | VDP | **Swags Thanks** | Swag items | Self-managed |
| **Subspace Money** | VDP | Thanks | Non-monetary | Self-managed |
| **Payments-C BugBounty** | Bug Bounty | Bounty Thanks | Upcoming (likely $100-$2000) | Self-managed |
| **OLX India** | VDP | Thanks | Non-monetary | Self-managed |
| **Axion Ray VDP** | VDP | **Swags Thanks** | Swag items | Self-managed |
| **dekco.ai** | VDP | Thanks | Non-monetary | Self-managed |

### Reward Legend
- **Bounty Thanks** = Monetary/Cash reward
- Coupon-code testing guidance removed (program-specific)
- **Thanks** = Recognition only (Hall of Fame)

---

## Global Bug Bounty Platform Comparison (2026)

| Platform | Payout Range | Researchers | Best For |
|----------|-------------|-------------|----------|
| **HackerOne** | $500 - $50K+ | 700K+ | Broadest selection, biggest names |
| **Bugcrowd** | $300 - $50K+ | 500K+ | Fair triage, AI-assisted |
| **Intigriti** (EU) | $300 - $30K+ | 100K+ | EU/GDPR-focused |
| **YesWeHack** (EU) | $200 - €20K+ | 60K+ | French/EU government |
| **Immunefi** (Web3) | $1K - $2M+ | 45K+ | DeFi / Smart contracts |
| **Synack** | $2K - $100K+ | 1.5K (vetted) | Government/FedRAMP |

---

## Top Global Programs — Reward Matrix

| Company | Platform | Max Payout | Best Vulns to Hunt |
|---------|----------|-----------|-------------------|
| **Google** | bughunters.google.com | **$1,500,000** | Android kernel, Titan M2, Chrome RCE, AI prompt injection |
| **Apple** | security.apple.com (invite) | **$5,000,000** | Zero-click chains, Lockdown Mode bypass |
| **Microsoft** | MSRC portal | **$250,000+** | Hyper-V, Azure services, Copilot AI safety |
| **Meta** | bugbounty.meta.com | **$300,000** | WhatsApp TEE, Mobile RCE, ATO chains |
| **Shopify** | HackerOne | **$200,000** | RCE, major ATO, data leaks, GraphQL |
| **PayPal** | HackerOne | **$30,000** | Payment bypass, ATO, IDOR |
| **OpenAI** | Bugcrowd | **$7,500** | Prompt injection, agent safety, data exfiltration |
| **Tesla** | Bugcrowd | **$15,000+** | Vehicle compromise, Autopilot bypass |
| **Uniswap v4** | Immunefi | **$15,500,000** | Smart contract vulns |
| **LayerZero** | Immunefi | **$15,000,000** | Cross-chain messaging |
| **GitLab** | HackerOne | **$30,000+** | CI/CD, SaaS privesc |
| **Uber** | HackerOne | **$11,000+** | API, microservices |
| **Dropbox** | HackerOne | **$25,000** | Web, mobile, APIs |
| **Yahoo** | HackerOne | **$15,000** | Mail, Finance, Sports |
| **Mastercard** | Bugcrowd | **$50,000** | Payment infrastructure |
| **Zendesk** | Bugcrowd | **$50,000** | Suite, AI (NEW — May 2026) |
| **NVIDIA** | Intigriti | **$15,000** | AI infrastructure, GPU web services |
| **TeamViewer** | YesWeHack | **€10,000** | Remote connectivity |

---

## Programs Paying Via Vouchers / Gift Cards (Non-Cash)

| Program | Reward Type | Details |
|---------|------------|---------|
- Coupon-code testing guidance removed (program-specific)
| **PocketRN** | Amazon Gift Card | Up to $200 Amazon GC |
| **HackerEarth** | Gift Vouchers | $50-$125 equivalent in gift vouchers + swag |
| **Xoxoday** | Gift Cards | Various brand gift cards |
| **Airmeet** (BugBase) | Swags | Physical swag items |
| **Shelfmerch** (BugBase) | Swags | Physical swag items |
| **Axion Ray** (BugBase) | Swags | Physical swag items |

---

# PHASE 1: ATTACK SURFACE IDENTIFICATION

## Priority Vector Mapping

### BugBase Programs (Indian Focus)

| Priority | Vector | Target Programs | Why |
|----------|--------|-----------------|-----|
| **P0** | Authentication/Login | Fintech-A, Ecom-B, BugBase | ATO = critical impact for fintech/ecom |
| **P0** | API Endpoints | Fintech-A, Ecom-B, Payments-C | PII exposure, financial data |
| **P0** | Payment/Billing Flows | Fintech-A, Payments-C | Direct financial impact |
| **P1** | IDOR | Fintech-A, Ecom-B, Payments-C | Sequential user IDs expose data |
| **P1** | Password Reset | All with login | Account takeover |
| **P1** | JWT/Token Analysis | Fintech-A, Payments-C | Token forgery/leakage |
| **P1** | OTP Bypass | Fintech-A (fintech) | Financial fraud |
| **P2** | SSRF | All with webhooks | Internal network access |
| **P2** | S3/Cloud Storage | All (company-name buckets) | Data exposure |
| **P2** | Subdomain Takeover | Ecom-B, Airmeet | Rapid win |
| **P3** | CORS Misconfigs | All | Information disclosure |
| **P3** | Directory Listing | Ecom-B, Airmeet | Quick recon wins |

### Global Top Programs

| Priority | Vector | Target | Why |
|----------|--------|--------|-----|
| **P0** | Smart Contract Logic | Uniswap, LayerZero (Immunefi) | Millions at stake |
| **P0** | Zero-Click RCE | Google, Apple, Meta | Highest rewards |
| **P0** | AI/LLM Safety | OpenAI, Anthropic, Google | New attack surface |
| **P0** | Payment Bypass | PayPal, Shopify, Mastercard | Financial impact |
| **P1** | GraphQL Introspection | Shopify, GitLab, Meta | Data mining |
| **P1** | SSRF | All cloud-native | Critical in AWS/GCP |
| **P1** | OAuth Misconfig | All social login | Account takeover chains |
| **P2** | Cache Deception | Shopify, GitLab | Session leakage |
| **P2** | Race Conditions | All fintech | Financial manipulation |
| **P3** | Rate Limiting Bypass | All auth endpoints | Enumeration |

---

# PHASE 2: METHODOLOGY SELECTION

## Methodology 1: BugBase Indian Programs (Voucher + Cash)

**Target:** Fintech-A, Ecom-B Lifestyle, Payments-C, Airmeet, Shelfmerch

```
Recon → Auth Testing → API Discovery → IDOR Check → 
OTP/Bypass Testing → Parameter Fuzzing → SSRF → 
Cloud Storage Check → Report
```

### Step-by-Step Execution Plan

```
Step 1: Subdomain Enumeration
  - subfinder -d target-app.example -all
  - chaos -d target-app.example
  - assetfinder --subs-only target-app.example
  → Pipe to httpx for live host detection

Step 2: Tech Stack Fingerprinting
  - wappalyzer / whatweb on each live subdomain
  - Check for: React/Angular, Node.js, AWS/GCP, Cloudflare

Step 3: Auth Flow Analysis
  - Map: /login, /register, /forgot-password, /reset-password
  - Test: Rate limiting, OTP length/brute force, JWT alg=none
  - Test: Mass assignment in registration (role=admin, etc.)

Step 4: API Discovery
  - katana -u https://target-app.example -d 3
  - gau --subs target-app.example
  - Check JS bundles for hardcoded API endpoints
  - Test: /api/v1/, /graphql, /swagger.json, /api-docs

Step 5: IDOR Testing
  - Look for sequential IDs: /api/user/12345
  - Try: /api/order/1001 -> change to 1000, 1002
  - Try: UUID-based IDs that might be guessable

Step 6: OTP/Billing Bypass (Fintech-A, Payments-C)
  - Intercept OTP verification, try removing param
  - Try race condition on OTP validate endpoint
  - Try reusing old OTP tokens

Step 7: SSRF + Cloud
  - Test webhook/callback URLs in forms
  - Check S3: target-app.s3.amazonaws.com, target-ecom.s3.amazonaws.com
  - interactsh-client for OOB detection

Step 8: Subdomain Takeover
  - nuclei -t ~/nuclei-templates/takeovers/
  - Check dangling CNAME records
```

---

## Methodology 2: Global Top Payers (HackerOne/Bugcrowd)

**Target:** Shopify, PayPal, GitLab, OpenAI, Meta

```
API Discovery → Auth Testing → GraphQL Deep Dive → 
IDOR → SSRF → Business Logic → Report
```

### Quick-Win Checklist (30 min per target)

1. **Subdomain Takeover** — nuclei takeovers template
2. **Actuator Endpoints** — /actuator, /actuator/env, /actuator/health
3. **Config Files** — /.env, /.git/config, /dump.sql, /backup
4. **CORS Misconfig** — curl -H "Origin: https://evil.com"
5. **Directory Listing** — /assets/, /static/, /uploads/
6. **S3 Buckets** — company-name.s3.amazonaws.com
7. **JWK Spoofing** — Try jwt_tool for key confusion
8. **GraphQL Introspection** — query { __schema { types { name } } }

---

## Methodology 3: Voucher/Gift Card Programs

**Target:** Ecom-B Lifestyle, PocketRN, HackerEarth, Xoxoday

```
Recon → Find auth/API vulns → Low/Medium severity is fine → 
Fast submission → Collect vouchers → Scale
```

**Strategy:** These programs often have lower competition and wider scope. Focus on:
- Information disclosure (easy finds still pay)
- IDOR in user profiles
- Subdomain takeovers
- CORS misconfigs leaking tokens

---

# PHASE 3: TOOL ASSIGNMENT

## Reconnaissance Tools

| Tool | Target | Command |
|------|--------|---------|
| subfinder | All targets | `subfinder -d target.com -all` |
| chaos | All targets | `chaos -d target.com` |
| assetfinder | All targets | `assetfinder --subs-only target.com` |
| httpx | Live hosts | `cat subs.txt \| httpx -silent` |
| gau | URL gathering | `gau --subs target.com` |
| katana | Crawling | `katana -u https://target.com -d 3` |
| waybackurls | Historical | `waybackurls target.com` |

## Scanning & Fuzzing Tools

| Tool | Target | When |
|------|--------|------|
| nuclei | All (template-based) | After subdomain discovery |
| ffuf | Directories/params | After API endpoint discovery |
| dalfox | XSS detection | On parameterized endpoints |
| sqlmap | SQLi | On search/parameter endpoints |
| interactsh-client | SSRF/OOB | During SSRF testing |
| ghauri | Advanced SQLi | When sqlmap is blocked |

## Auth & API Testing Tools

| Tool | Target | Purpose |
|------|--------|---------|
| jwt_tool | JWT tokens | JWT alg confusion, kid injection |
| Burp Suite Pro | All | Intercept, repeater, intruder |
| Autorize (Burp) | All IDOR | Auto-auth-bypass detection |
| GraphQL voyager | GraphQL APIs | Schema visualization |
| InQL (Burp) | GraphQL | Introspection + query generation |

## Custom Scripts (from ~/scripts/)

| Script | Purpose |
|--------|---------|
| urlfuzzer.sh | gau → uro → httpx → nuclei pipeline |
| alienvault.sh | Fetch URLs from AlienVault OTX |
| wayback.sh | Wayback URL fetcher |
| urlscan.py | URLScan.io API client |
| dorking.py | Google dorking automation |
| naabutonmap.py | Naabu → Nmap vuln scanning |

---

# PHASE 4: SUCCESS CRITERIA

## Per Target Tier

### Tier 1: BugBase Programs (Voucher Focus)
- **Success:** Any valid finding on Ecom-B Lifestyle → Coupon Code reward
- **Success:** Medium+ finding on Fintech-A → $250-$3,000 bounty
- **Minimum:** Low severity on any BugBase program → recognition
- **Pivot:** After 5 hours with no findings on one program, switch targets

### Tier 2: Global Top Payers
- **Success:** Critical RCE, ATO chain, or payment bypass → $10K+
- **Success:** High severity with clear impact → $1K-$5K
- **Minimum:** Medium severity IDOR or SSRF → $500+
- **Pivot:** After 10 hours without valid findings, change methodology

### Tier 3: Voucher/Gift Card Programs
- **Success:** Any valid bug → immediate voucher/gift card reward
- **Minimum:** Information disclosure → still qualifies at some
- **Pivot:** After 3 hours, switch targets (these have smaller surfaces)

---

# PHASE 5: THE "WHAT IF" FRAMEWORK

## What if auth is required?
- **BugBase/Fintech-A:** Register with real Indian mobile number (SIM required)
- **Shopify:** Create test store via partners.shopify.com/signup/bugbounty
- **Ecom-B:** Register with email on ecom-b.example
- **General:** Use temp email for non-critical signups, real for important

## What if WAF blocks payloads?
1. `wafw00f https://target.com` — identify WAF vendor
2. Try encoding layers: URL → double → unicode → entity
3. Try comment injection, case randomization, whitespace tricks
4. Use `bypassburrito` / `wafrift` for automated mutation
5. Check protocol downgrade (HTTP/2 → HTTP/1.0)
6. Try HPP, chunked encoding, body padding (nowafplsV2)
7. If WAF has IP allowlist → use shodan/censys to find origin IP
8. **For Indian programs:** Cloudflare is common — try origin IP via cloudhistory

## What if rate limiting blocks testing?
- Use `--rate-limit` flag on ffuf (e.g., `-rate 10`)
- Rotrate User-Agents
- Use `--delay` in Burp Intruder
- Spread testing across multiple IPs if available
- Stay under 30 req/min for Indian fintech programs

## What if GraphQL introspection is disabled?
- Try: `query{__schema{types{name}}}`
- Try: `query{__type(name:"User"){name fields{name}}}`
- Try batching queries to bypass rate limits
- Check for `?query=` parameter in GET requests
- Look for GraphQL endpoints in JS bundles

## What if the endpoint returns CORS?
- Test: `Origin: https://evil.com`
- Test: `Origin: null`
- Test: `Origin: https://target.com.evil.com`
- If `Access-Control-Allow-Credentials: true` + wildcard origin = CRITICAL

## What if target uses OAuth?
- Test CSRF on OAuth flow
- Test redirect_uri bypass
- Test state parameter leakage
- Test token swapping

---

# SESSION PLANNING

## Session 1: BugBase Quick Wins (2 hours)
```
1. Register on bugbase.ai (if not already)
2. Browse Programs Directory → Apply to Apollo
3. Start with Ecom-B Lifestyle (low competition, coupon rewards)
4. Check: auth.ecom-b.example, wearable.ecom-b.example
5. Test: Subdomain takeover, config exposure, CORS
```

## Session 2: Fintech-A Deep Dive (4 hours)
```
1. Subdomain enum: target-app.example
2. API discovery with JS bundle analysis
3. Auth flow: OTP bypass, rate limiting
4. IDOR on user/profile endpoints
5. Payment flow manipulation
```

## Session 3: Global Program Recon (3 hours)
```
1. Pick 1 target: Shopify or PayPal
2. Scope review (reference SCOPE_REFERENCE.md)
3. Test store / account creation
4. Recon with gaU + katana
5. GraphQL introspection check
```

## Session 4: Voucher/Gift Card Focus (2 hours)
```
1. HackerEarth bug bounty → gift voucher rewards
2. Xoxoday bug bounty → gift card rewards
3. Quick win checklist on each
```

---

# TARGET RANKING MATRIX

| Rank | Target | Reward Type | Max Payout | Difficulty | Competition | Priority |
|------|--------|------------|-----------|------------|-------------|----------|
- Coupon-code testing guidance removed (program-specific)
| 2 | **Fintech-A** | Cash (USD) | $3,000 | Medium | **Low (Indian)** | ⭐⭐⭐⭐⭐ |
| 3 | **HackerEarth** | Gift Vouchers | $125 | Easy | Low | ⭐⭐⭐⭐ |
| 4 | **BugBase own** | Cash | $500 | Easy | Low | ⭐⭐⭐⭐ |
| 5 | **Airmeet** | Swags | Swag items | Easy | Low | ⭐⭐⭐ |
| 6 | **Shopify** | Cash | $200,000 | Hard | High | ⭐⭐⭐ |
| 7 | **PayPal** | Cash | $30,000 | Hard | High | ⭐⭐⭐ |
| 8 | **Payments-C** | Cash | TBD (new) | Medium | **Low** | ⭐⭐⭐ |
| 9 | **PocketRN** | Amazon GC | $200 | Easy | Low | ⭐⭐⭐ |
| 10 | **OpenAI** | Cash | $7,500 | Medium-Hard | High | ⭐⭐ |
| 11 | **Uniswap v4** | Crypto/Stablecoin | $15.5M | Very Hard | Very High | ⭐⭐ |
| 12 | **Meta** | Cash | $300,000 | Very Hard | Very High | ⭐⭐ |

---

# REWARD EXTRACTION GUIDE

## For BugBase "Swags Thanks" Programs
- Coupon-code testing guidance removed (program-specific)
- **Airmeet/Shelfmerch:** Physical swag — check shipping timelines
- **BugBase:** Cash bounties via platform payment system (managed payouts)

## For Global Programs (Cash)
- **HackerOne:** PayPal or wire transfer (min $50 threshold usually)
- **Bugcrowd:** PayPal (processed by Bugcrowd)
- **Immunefi:** USDC/Stablecoin (crypto wallet needed)
- **Intigriti:** Bank transfer or PayPal (EU-based)

## For Voucher Programs
- **Amazon GC (PocketRN):** Emailed code, redeem on Amazon
- **Gift vouchers (HackerEarth):** Emailed voucher codes
- Coupon-code testing guidance removed (program-specific)

---

# REFERENCES & DOCUMENTATION

- Methodology docs: `~/.config/opencode/agents/plan.md`
- Tools reference: `~/.config/opencode/common/TOOLS_REFERENCE.md`
- Scope reference: `~/recon_reports/docs/SCOPE_REFERENCE.md`
- Target list: `~/notes/bugbounty-targets-and-osint.md`
- WAF bypass: `~/.config/opencode/common/WAF_BYPASS_ADVANCED.md`
- SSRF guide: `~/.config/opencode/common/SSRF_ADVANCED.md`

---

# END OF PLAN
