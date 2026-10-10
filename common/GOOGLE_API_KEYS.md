# : Finding & Exploiting Exposed Google API Keys for Bug Bounties
- Source: (May 23, 2026) — infosecwriteups.com
- Gemini API keys can lead to high-impact bounties via unauthorized AI service access

## Why Google API Keys Are Worth Hunting
- Exposed Google API keys were historically low-value, but Gemini ecosystem changed this
- A single leaked Gemini-enabled key grants access to powerful AI services
- Real-world abuse scenarios with serious financial impact from unauthorized usage

## Phase 1: GitHub Dorking (Starting Point)
```bash
# Search for Google API keys in GitHub
# Common patterns to search for:
# AIza[0-9A-Za-z_-]{35}  (Google API key format)
# "AIza" + "gemini" / "gemini-2.0" / "generative-ai"
# "GOOGLE_API_KEY" environment variable leaks
# .env files, config files, JS bundles
```

## Phase 2: Key Verification
```bash
# Validate Gemini access via models endpoint
curl -s "https://generativelanguage.googleapis.com/v1beta/models?key=AIza..."
# Check for gemini-2.0-pro, gemini-2.0-flash, etc.
# A valid response means the key has Gemini enabled
```

## Phase 3: Demonstrating Impact
- Move beyond "found a key" — show what the key can actually do
- Access Gemini API endpoints and demonstrate model interaction
- Show cost impact via pricing calculator estimation
- Test referer-based bypasses (some keys have HTTP referrer restrictions)

## Phase 4: Burp Suite Extension — Automated In-Browser Discovery
- Dedicated Burp extension for intercepting API keys during browsing
- Automatically checks JavaScript files and page sources
- Validates discovered keys against Gemini endpoints

## Phase 5: Full Automation Tool (5 Modes)
- Mode 1 — Single domain: Crawl target, extract API keys from page source + JS, validate Gemini access
- Mode 2 — Multi-domain: Sequential/parallel execution across domains
- Mode 3 — Direct JS URL list: Skip crawling, scan pre-collected JS URLs (from GoSpider/Katana)
- Mode 4 — Raw key validation: Accept list of keys, validate + referer bypass testing
- Mode 5 — Validated capabilities with evidence: List every accessible endpoint + model, curl commands, truncated responses, attach output files (.png, .mp4, .mp3), add cost breakdown

## Phase 6: Testing Beyond Gemini
- Google Cloud APIs (Cloud Storage, Compute Engine, BigQuery)
- Each API has different validation endpoints
- Check if key is unrestricted vs restricted to specific services

## Financial Impact Reporting
- Estimate cost per request on current API pricing
- Calculate potential abuse cost for the organization
- Demonstrate unauthorized service access with screenshots

## Key Commands
```bash
# Extract API keys from JS files
cat urls.txt | while read url; do curl -s "$url" | grep -oP 'AIza[0-9A-Za-z_-]{35}'; done

# Validate keys at scale
cat keys.txt | while read key; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://generativelanguage.googleapis.com/v1beta/models?key=$key")
  echo "$key: $status"
done

# Test referer bypass (if key restricted to specific domains)
curl -s -H "Referer: https://allowed-domain.com" \
  "https://generativelanguage.googleapis.com/v1beta/models?key=$key"
```
