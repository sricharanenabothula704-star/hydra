# Bug Bounty Program Scope & Policy Reference

## Top Programs Quick Reference

### HackerOne Programs
| Program | Platform | Max Bounty | Key Scope |
|---------|----------|-----------|-----------|
| Google VRP | HackerOne | $1,500,000 | *.google.com, Android, Chrome, AI |
| PayPal | HackerOne | $30,000 | *.paypal.com, *.venmo.com, *.braintree.com |
| Shopify | HackerOne | $200,000 | *.shopify.com, Shopify admin, GraphQL |
| GitLab | HackerOne | $30,000 | GitLab.com SaaS, self-managed EE |
| Uber | HackerOne | $11,000+ | *.uber.com, *.ubereats.com, APIs |
| Dropbox | HackerOne | $25,000 | dropbox.com, APIs, mobile apps |
| Yahoo | HackerOne | $15,000 | *.yahoo.com, *.aol.com, *.techcrunch.com |

### Bugcrowd Programs
| Program | Platform | Max Bounty | Key Scope |
|---------|----------|-----------|-----------|
| Tesla | Bugcrowd | $15,000+ | *.tesla.com, vehicle software, energy |
| OpenAI | Bugcrowd | $7,500 | ChatGPT, GPT-4/5, DALL-E, Operator |
| Mastercard | Bugcrowd | $50,000 | *.mastercard.com, APIs, gateways |
| Atlassian | Bugcrowd | $3,000 | Jira, Confluence, Bitbucket Cloud |
| Zendesk | Bugcrowd | $50,000 | Zendesk Suite, AI, mobile apps |

### Other Platforms
| Program | Platform | Max Bounty | Key Scope |
|---------|----------|-----------|-----------|
| Apple | Self-hosted | $5,000,000 | iOS, macOS, iCloud, WebKit (invite-only) |
| Microsoft | Self-hosted | $250,000+ | Azure, M365, Windows, Copilot |
| Meta | Self-hosted | $300,000 | FB, IG, WA, Quest, Threads |
| NVIDIA | Intigriti | $15,000 | Web, developer portals, CUDA |
| TeamViewer | YesWeHack | €10,000+ | Remote, DEX (wildcard scope) |
| Uniswap v4 | Immunefi | $15,500,000 | Smart contracts (Web3) |
| LayerZero | Immunefi | $15,000,000 | Cross-chain messaging (Web3) |

## Policy Rules (Common Across Programs)

### Do's
- Read the full scope before testing ANYTHING
- Stay strictly within in-scope targets
- Use test accounts when possible
- Report clearly with PoC
- Follow responsible disclosure timelines
- Respect rate limits

### Don'ts
- No social engineering
- No physical attacks
- No DoS/DDoS attacks
- No mass automated scanning without permission
- No accessing other users' data beyond PoC
- No public disclosure without approval
- No testing out-of-scope assets

### Disclosure Rules
| Program | Disclosure Policy |
|---------|------------------|
| Most HackerOne | No public disclosure without program consent |
| Google VRP | No disclosure without consent; safe harbor |
| Microsoft MSRC | Coordinated Vulnerability Disclosure; 30-day cooldown |
| Apple | PRIVATE program (invite-only for top categories) |
| Bugcrowd Standard | Standard disclosure terms per program |
| Immunefi | PoC required; KYC for high-value rewards |

### Safe Harbor
Most major programs (Google, Microsoft, Meta, Apple, PayPal) provide safe harbor under CFAA and similar laws, meaning:
- Research conducted in compliance with program policy is authorized
- No legal action will be taken against researchers
- Researchers are protected from DMCA/CFAA claims

## VDP vs Bug Bounty
| Aspect | VDP | Bug Bounty |
|--------|-----|-----------|
| Monetary Reward | No | Yes |
| Safe Harbor | Usually | Yes |
| Testing Authorization | Yes | Yes |
| Hall of Fame | Often | Usually |
| Scope | Often broader | Often narrower |

## Platform-Specific Submission Formats

### BugBase
- Fields: Scope, Vulnerability Type, Severity (CVSS picker), Title, Summary, PoC, Impact, Steps to Reproduce, Specifics, Recommendations
- Max video size: 25MB
- Reports are non-editable after submission
- CVSS calculator built-in

### HackerOne
- Fields: Vulnerability Type (CWE), Severity (CVSS), Asset, Description, Steps to Reproduce, Impact, Attack Scenario, Supporting Material
- Supports markdown
- Can edit reports after submission until triaged

### Bugcrowd
- Fields: Vulnerability Type (VRT taxonomy), Severity (P1-P5), Target, Description, Steps to Reproduce, Impact, Remediation
- Uses Bugcrowd VRT for severity
- Supports attachments up to 25MB
