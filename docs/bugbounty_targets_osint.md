# Bug Bounty Programs — Targets, Scope & Policy Rules
# OSINT Leaked Data Sources & Tools
# Generated: July 2026

================================================================================
PART 1: TOP BUG BOUNTY PROGRAMS
================================================================================

----------------------------------------------------------------------
1. GOOGLE VRP (Android & Chrome)
----------------------------------------------------------------------
Platform:      HackerOne + bughunters.google.com
In-Scope:      *.google.com, Chrome browser (all channels), Android OS,
               Google devices (kernel, Trusty TEE, Titan M2, secure element),
               Gemini, Workspace AI, Search, Cloud Platform
Out-of-Scope:  Third-party services, social engineering, physical attacks,
               DoS on non-critical, known bugs
Rewards:       Android: up to $1,500,000 (zero-click Titan M2 exploit)
               Chrome: up to $250,000 full-chain + $250,128 MiraclePtr bonus
               Standard: $500 base
Policy:        Safe harbor; no disclosure without consent; AI-assisted
               reports deprioritized; must use latest OS/hardware
URL:           https://bughunters.google.com

----------------------------------------------------------------------
2. MICROSOFT (MSRC)
----------------------------------------------------------------------
Platform:      Self-hosted + Intigriti (payments)
In-Scope:      Azure (up to $60K), M365/Office 365 (up to $19.5K),
               Windows Insider Preview (up to $100K), Hyper-V ($250K+),
               Dynamics 365, Power Platform, AI bounty (Copilot)
Out-of-Scope:  Known vulns, versions outside latest, RAS server components
Rewards:       Azure: $1,250-$60,000; Windows: $500-$100,000;
               Hyper-V: up to $250,000
Policy:        "In-scope by default" since Dec 2025; coordinated disclosure;
               30-day cooldown for third-party CVEs

----------------------------------------------------------------------
3. APPLE SECURITY BOUNTY
----------------------------------------------------------------------
Platform:      Self-hosted (security.apple.com/bounty) - PRIVATE (invite-only)
In-Scope:      iOS, iPadOS, macOS, visionOS, watchOS, tvOS, iCloud,
               WebKit, Secure Enclave, kernel, TCC, Gatekeeper, wireless/radio
Out-of-Scope:  Third-party apps, lower OS versions, jailbroken devices
Rewards:       Zero-click remote chain: $2,000,000 (up to $5M with Lockdown Mode)
               One-click: $1,000,000; Wireless proximity: $1,000,000
               Physical locked device: $500,000; Sandbox escape: $500,000
Policy:        Target Flags system for automated verification; beta bonuses;
               Lockdown Mode bypass bonuses

----------------------------------------------------------------------
4. META (Facebook, Instagram, WhatsApp)
----------------------------------------------------------------------
Platform:      Self-hosted (bugbounty.meta.com)
In-Scope:      Facebook, Instagram, Messenger, WhatsApp, Threads
               (web+mobile), Meta Quest, Ray-Ban Meta glasses,
               Graph API, developer platforms, WhatsApp Private Processing
Out-of-Scope:  Third-party apps, social engineering, DoS
Rewards:       Mobile RCE: up to $300,000; WhatsApp TEE: up to $300,000
               Account Takeover (0-click): up to $130,000
               Data Abuse: avg $37,250
Policy:        Hacker Plus bonus multiplier; safe harbor under CFAA

----------------------------------------------------------------------
5. PAYPAL
----------------------------------------------------------------------
Platform:      HackerOne
In-Scope:      *.paypal.com, *.venmo.com, *.xoom.com, *.braintreepayments.com,
               *.braintreegateway.com, *.hyperwallet.com, *.paypalcorp.com,
               *.paylution.com, *.paydiant.com, mobile apps (PayPal, Venmo,
               Braintree, Xoom), py.pl, paypalobjects.com, paypal.me,
               api.loanbuilder.com, api.swiftfinancial.com
Out-of-Scope:  *.paypal.cn, braintree.com, *.atlassian.net
Rewards:       $50 - $30,000 (recently increased from $20K max)
Policy:        CVSS-based scoring; no disclosure without approval; safe harbor
URL:           https://hackerone.com/paypal

----------------------------------------------------------------------
6. SHOPIFY
----------------------------------------------------------------------
Platform:      HackerOne
In-Scope:      *.shopify.com, *.shopifyapps.com, myshopify.com,
               Shopify admin, storefront, checkout, Shop app (iOS/Android),
               POS, APIs, Partners area, GraphQL endpoints
Out-of-Scope:  Third-party apps, live merchant stores (test stores only)
Rewards:       Up to $200,000 (critical findings)
Policy:        Must use test accounts via partners.shopify.com/signup/bugbounty
URL:           https://hackerone.com/shopify

----------------------------------------------------------------------
7. GITLAB
----------------------------------------------------------------------
Platform:      HackerOne
In-Scope:      GitLab.com SaaS, self-managed EE, CI/CD infrastructure,
               gitlab.com, about.gitlab.com (static), API endpoints
Out-of-Scope:  Third-party deps, DoS
Rewards:       Up to $30,000+; Critical: $5K-$30K; High: $1K-$5K
Policy:        30-day waiting period before public disclosure;
               researchers with 3+ valid reports get 1-year Ultimate license
URL:           https://hackerone.com/gitlab

----------------------------------------------------------------------
8. UBER
----------------------------------------------------------------------
Platform:      HackerOne
In-Scope:      *.uber.com, *.ubereats.com, *.uberinternal.com,
               Rider/Driver/Eats apps, vault.uber.com, partners.uber.com,
               developers.uber.com, APIs, microservices
Out-of-Scope:  *.ubercarshare.com, *.uberscoot.us, *.ubertransit.io,
               newsroom.uber.com, eng.uber.com, brand.uber.com
Rewards:       $300 - $11,000+ (chains higher)
Policy:        Pay-At-Triage (14 days); CVSS 3.1 + Environmental modifiers
URL:           https://hackerone.com/uber

----------------------------------------------------------------------
9. DROPBOX
----------------------------------------------------------------------
Platform:      HackerOne
In-Scope:      dropbox.com, *.dropbox.com, web app, desktop client,
               mobile apps (iOS/Android), APIs, Paper, HelloSign,
               infrastructure and corporate network assets
Out-of-Scope:  Third-party integrations, social engineering, DoS
Rewards:       Up to ~$25,000; Critical: $10K-$25K
Policy:        Bounty matching to charity; coordinated disclosure
URL:           https://hackerone.com/dropbox

----------------------------------------------------------------------
10. YAHOO (Yahoo Paranoids)
----------------------------------------------------------------------
Platform:      HackerOne
In-Scope:      *.yahoo.com, *.aol.com, *.techcrunch.com, *.engadget.com,
               *.autoblog.com, Yahoo Mail/Finance/Sports/News,
               AOL Mail, mobile apps
Out-of-Scope:  Third-party ad networks
Rewards:       Critical: up to $15,000+
URL:           https://hackerone.com/yahoo

----------------------------------------------------------------------
11. TESLA (Bugcrowd)
----------------------------------------------------------------------
Platform:      Bugcrowd
In-Scope:      *.tesla.com, *.tesla.cn, *.teslamotors.com, *.tesla.services,
               *.solarcity.com, *.teslainsuranceservices.com, vehicle software,
               Autopilot, PowerWall, solar, iOS/Android apps,
               all hosts in Tesla IP space
Out-of-Scope:  energysupport.tesla.com, ir.tesla.com, shop.eu.teslamotors.com,
               engage.tesla.com
Rewards:       Up to $15,000+ (full vehicle exploits)
Policy:        Bugcrowd standard disclosure; GPG encrypted reports also accepted
URL:           https://bugcrowd.com/tesla

----------------------------------------------------------------------
12. OPENAI
----------------------------------------------------------------------
Platform:      Bugcrowd
In-Scope:      ChatGPT (web+API), GPT-4/GPT-5, DALL-E, Codex, Operator,
               Atlas Browser, Connectors/MCP integrators
               Safety Bounty: prompt injection, data exfiltration by agent,
               account/platform integrity bypasses
Out-of-Scope:  General jailbreaks, content-policy bypasses with no safety impact
Rewards:       Safety: up to $7,500; Security: $500-$6,500+
Policy:        KYC may be required; separate Safety and Security programs
URL:           https://bugcrowd.com/openai

----------------------------------------------------------------------
13. MASTERCARD (Bugcrowd)
----------------------------------------------------------------------
Platform:      Bugcrowd
In-Scope:      *.mastercard.com, APIs, payment gateways, mobile apps,
               connected services, merchant platforms
Out-of-Scope:  Third-party merchant sites, physical POS
Rewards:       Up to ~$50,000; Critical: $10K-$50K
URL:           https://bugcrowd.com/mastercard

----------------------------------------------------------------------
14. ATLASSIAN (Bugcrowd)
----------------------------------------------------------------------
Platform:      Bugcrowd
In-Scope:      Jira Cloud, Confluence Cloud, Bitbucket Cloud, Trello,
               Opsgenie, Statuspage, *.atlassian.com, *.jira.com,
               *.bitbucket.org
Out-of-Scope:  On-premises versions, acquired companies' platforms
Rewards:       $100 - $3,000 (direct); Marketplace: P1 $1,500
Policy:        Public program since 2017
URL:           https://bugcrowd.com/atlassian

----------------------------------------------------------------------
15. ZENDESK (Bugcrowd)
----------------------------------------------------------------------
Platform:      Bugcrowd (NEW - May 2026)
In-Scope:      Zendesk Suite, Zendesk AI, Zendesk Front End,
               Marketplace Apps (Zendesk-created), mobile apps,
               public repositories
Out-of-Scope:  Zendesk for Sales/Sell, support.zendesk.com, www.zendesk.com
Rewards:       $100 - $50,000 (P1 Critical: up to $50K)
URL:           https://bugcrowd.com/zendesk

----------------------------------------------------------------------
16. NVIDIA (Intigriti)
----------------------------------------------------------------------
Platform:      Intigriti
In-Scope:      NVIDIA corporate web, developer portals, GPU/Driver web services,
               AI infrastructure (CUDA, NGC)
Out-of-Scope:  Hardware/Firmware, already-patched CVEs
Rewards:       $150 - $15,000
URL:           https://app.intigriti.com/programs/nvidia

----------------------------------------------------------------------
17. TEAMVIEWER (YesWeHack)
----------------------------------------------------------------------
Platform:      YesWeHack
In-Scope:      TeamViewer Remote (desktop, mobile, web), TeamViewer DEX,
               wildcard scope ("essentially a wildcard")
Rewards:       Up to €10,000+
URL:           https://yeswehack.com/programs/teamviewer

----------------------------------------------------------------------
18. UNISWAP V4 (Immunefi - Web3)
----------------------------------------------------------------------
Platform:      Immunefi
In-Scope:      Uniswap v4 core smart contracts, periphery contracts,
               hooks-based architecture, concentrated liquidity pools
Rewards:       Up to $15,500,000 (Critical)
Policy:        PoC required; open submission; no staking required
URL:           https://immunefi.com/bounty/uniswap

================================================================================
PART 2: OSINT LEAKED DATA SOURCES & TOOLS
================================================================================

----------------------------------------------------------------------
BREACH/LEAK SEARCH ENGINES (Paid/Freemium)
----------------------------------------------------------------------
DeHashed      https://dehashed.com              - Billions records, email/username/password/IP search
IntelX        https://intelx.io                  - Deep/dark web + paste + Telegram + breach data
LeakCheck     https://leakcheck.io               - Email/username/keyword/domain/password search
Snusbase      https://snusbase.com               - Fastest lookup, plaintext results, daily updates
LeakRadar     https://leakradar.io               - 510B+ lines, infostealer logs, combolists
OSINTLeak     https://osintleak.com              - 17+ search selectors, AI-powered
Intelonio     https://intelon.io                 - 326B+ records, 500+ breach sources
Hudson Rock   https://www.hudsonrock.com         - Infostealer malware compromise check
Breachsense   https://www.breachsense.com        - Dark web monitoring

----------------------------------------------------------------------
BREACH/LEAK SEARCH ENGINES (Free)
----------------------------------------------------------------------
HaveIBeenPwned     https://haveibeenpwned.com         - Check email/domain
Leaked.Domains     https://leaked.domains             - Domain leaked credentials
Leak-Lookup        https://leak-lookup.com             - 3B+ records / 3000+ DBs
PSBDMP             https://psbdmp.ws                  - Pastebin dump search
Library of Leaks   https://search.libraryofleaks.org  - Search leak documents
XposedOrNot        https://xposedornot.com             - Free breach check
ProxyNova COMB     https://proxynova.com               - COMB (3.2B+ credentials)
AntiPublic         https://antipublic.net              - Billions email/password pairs
CLIS               https://c-leaks.com                 - 1B+ records / 671+ datasets
CredenShow         https://credenshow.ru               - Deep web breach search
WhiteIntel         https://whiteintel.io               - Dark web data leak search
InfoStealers.info  https://infostealers.info           - Indexed infostealer logs
BF Search          https://bf.based.re                 - BreachForums user data
HaveIBeenRansom    https://haveibeenransom.com         - Ransomware leak sites

----------------------------------------------------------------------
TELEGRAM BOTS FOR LEAKED DATA
----------------------------------------------------------------------
@LeakCheck_bot       - Official LeakCheck Telegram bot
@BreachFind_Bot      - OSINT bot for finding data among leaks
@Breached_DataBot    - Searches for data breach info
@NewLeakOSINT1bot    - Queries BreachForums leaked datasets
@Leakrus_bot         - Search emails, passwords, phones, addresses
@Impsel1erbot        - Backup leak search bot

----------------------------------------------------------------------
PASTEBIN / DUMP MONITORING
----------------------------------------------------------------------
PSBDMP            https://psbdmp.ws                    - REST API, search by keyword
pastebin-scraper  https://github.com/0x1F601/pastebin-scraper  - Real-time monitoring
Hunchly           https://www.hunch.ly                - OSINT capture with Pastebin integration

Google Dorks for Pastebin:
  site:pastebin.com "targetdomain"
  site:pastebin.com "password" "targetdomain.com"
  site:pastebin.com "DB_PASSWORD"
  site:pastebin.com filetype:txt "confidential"
  site:pastebin.com "API_KEY"

----------------------------------------------------------------------
OSINT FRAMEWORKS
----------------------------------------------------------------------
OSINT Framework   https://osintframework.com      - Visual map of OSINT tools
Maltego           https://www.maltego.com         - Graph-based relationship mapping
SpiderFoot HX     https://spiderfoot.net          - 200+ modules, automated queries
Recon-ng          https://github.com/lanmaster53/recon-ng  - Modular recon framework
theHarvester      https://github.com/laramies/theHarvester - Email/domain/host enumeration
Amass             https://github.com/owasp-amass/amass     - Subdomain/infrastructure discovery
Sherlock          https://github.com/sherlock-project/sherlock  - Username across 400+ platforms
Maigret           https://github.com/soxoj/maigret       - Advanced username search
WhatsMyName       https://whatsmyname.app        - Username enumeration
Shodan            https://shodan.io              - Internet-connected device search
Censys            https://search.censys.io       - Infrastructure / certificate search

----------------------------------------------------------------------
CLI TOOLS FOR BREACH CHECKING
----------------------------------------------------------------------
h8mail        pip install h8mail         - Check email in breaches
WhatBreach    https://github.com/Ekultek/WhatBreach
breach-parse  https://github.com/hmaverickadams/breach-parse
Leaker        https://github.com/vflame6/leaker  - Searches 10 breach DBs simultaneously

----------------------------------------------------------------------
GOOGLE DORKS FOR LEAKED DATA
----------------------------------------------------------------------
.env files:    site:target.com ext:env OR inurl:.env
               site:target.com inurl:.env ("DB_PASSWORD" OR "AWS_SECRET_KEY")
Git leaks:     site:target.com inurl:.git ("HEAD" OR "config")
               site:target.com inurl:(.gitconfig OR .git-credentials)
SQL dumps:     site:target.com filetype:(sql OR zip OR tar OR gz) ("CREATE TABLE")
Credentials:   site:target.com ("API_KEY" OR "apiKey" OR "PRIVATE KEY-----")
               site:target.com ("password" OR "passwd") filetype:txt
Directory:     intitle:"index of" "passwords" | "backup" | "config" | "database"
Exposed xls:   filetype:xls inurl:"email" inurl:"password"
Exposed csv:   filetype:csv "username" "password"
Exposed logs:  filetype:log "password" "putty"
Exposed conf:  filetype:conf "root" "password"

================================================================================
PART 3: 2026 MAJOR BREACHES (Confirmed)
================================================================================
Klue-Salesforce OAuth Token Breach - Jun 2026 - Supply chain (LastPass, HackerOne, etc.)
KDDI Email System                  - Jun 2026 - 14.22M accounts exposed
149M Credential Database           - Jan 2026 - Aggregated infostealer logs
1B Record Exposure                 - Mar 2026 - Names, phones, addresses (26 countries)
Government Officials Credentials   - Apr 2026 - 3,500+ legislators' emails + 750 plaintext pws
FortiBleed                         - Jun 2026 - Fortinet firewall credentials (194 countries)
University of Hawai'i              - Feb 2026 - 1.2M individuals, ransomware

================================================================================
PLATFORM COMPARISON
================================================================================
Platform      Payout Range          Researchers    Best For
HackerOne     $500 - $50K+           700K+         Broadest selection, biggest names
Bugcrowd      $300 - $50K+           500K+         Fair triage, AI-assisted triage
Intigriti     $300 - $30K+           100K+         EU researchers, GDPR/DORA
YesWeHack     $200 - €20K+            60K+         French/EU government
Immunefi      $1K - $2M+              45K+         Web3/DeFi smart contracts
Synack        $2K - $100K+             1.5K        Government, FedRAMP (vetted only)

================================================================================
TARGET DEFINITIONS (Recommended Attack Surface)
================================================================================

# Primary Targets (Highest Reward / Broad Scope)
TARGET_01: Google (bughunters.google.com)
  Scope: *.google.com, Android, Chrome, AI products
  Max Reward: $1,500,000
  Focus: Titan M2, Kernel, Chrome memory safety, AI prompt injection

TARGET_02: Apple (security.apple.com - invite only)
  Scope: iOS, macOS, iCloud, WebKit
  Max Reward: $5,000,000
  Focus: Zero-click chains, Lockdown Mode bypass

TARGET_03: Microsoft (MSRC portal)
  Scope: Azure, M365, Windows, Copilot AI
  Max Reward: $250,000+
  Focus: Hyper-V, Azure services, AI safety

TARGET_04: Meta (bugbounty.meta.com)
  Scope: Facebook, Instagram, WhatsApp, Quest
  Max Reward: $300,000
  Focus: Mobile RCE, WhatsApp TEE, ATO chains

TARGET_05: PayPal (HackerOne)
  Scope: *.paypal.com, *.venmo.com, *.braintreepayments.com, mobile apps
  Max Reward: $30,000
  Focus: Payment bypass, ATO, IDOR

TARGET_06: Shopify (HackerOne)
  Scope: *.shopify.com, *.shopifyapps.com, GraphQL
  Max Reward: $200,000
  Focus: RCE, major ATO, data leaks

TARGET_07: OpenAI (Bugcrowd)
  Scope: ChatGPT, GPT-4/5, DALL-E, Operator
  Max Reward: $7,500 (safety)
  Focus: Prompt injection, agent safety, data exfiltration

TARGET_08: Tesla (Bugcrowd)
  Scope: *.tesla.com, vehicle software, energy products
  Max Reward: $15,000+
  Focus: Vehicle compromise, Autopilot bypass

TARGET_09: NVIDIA (Intigriti)
  Scope: Web properties, developer portals, CUDA, NGC
  Max Reward: $15,000
  Focus: AI infrastructure, GPU web services

TARGET_10: Uniswap v4 (Immunefi)
  Scope: Smart contracts, periphery, hooks
  Max Reward: $15,500,000
  Focus: Smart contract vulnerabilities, critical logic bugs

# Additional Targets (Good for Building Reputation)
TARGET_11: GitLab (HackerOne) - Up to $30K - CI/CD, SaaS
TARGET_12: Uber (HackerOne) - Up to $11K+ - APIs, microservices
TARGET_13: Dropbox (HackerOne) - Up to $25K - Web, mobile, APIs
TARGET_14: Yahoo (HackerOne) - Up to $15K - Mail, Finance, Sports
TARGET_15: Mastercard (Bugcrowd) - Up to $50K - Payment infrastructure
TARGET_16: Zendesk (Bugcrowd) - Up to $50K - Suite, AI (NEW program)
TARGET_17: Atlassian (Bugcrowd) - Up to $3K - Jira, Confluence, Bitbucket
TARGET_18: TeamViewer (YesWeHack) - Up to €10K - Remote connectivity
TARGET_19: L'Oréal (YesWeHack) - Up to €5K - E-commerce, APIs
TARGET_20: LayerZero (Immunefi) - Up to $15M - Cross-chain messaging

================================================================================
END OF FILE
================================================================================
