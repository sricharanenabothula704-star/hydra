# Recon.exe — Bug Bounty Reconnaissance Methodology


---

## 1. Wayback Machine — Bypassing 404/403 Restrictions

**Concept:** When a URL returns 404 Not Found or 403 Forbidden on the live server, the resource may still exist in historical archives (archive.org). Wayback Machine takes snapshots over time.

**Why it works:**
- Companies change their apps — old endpoints get removed or locked down
- Wayback Machine still has the archived version
- The archived version may reveal legacy dashboards, visitor logs, internal host IPs, or top visited endpoints

**How to use:**
1. Install the Wayback Machine browser extension (Chrome/Firefox)
2. When a page returns 404/403, click the extension icon
3. Check if archived snapshots exist
4. Browse the archived version

**Timestamp [00:38]:** Accessing a 404 page via Wayback exposed legacy dashboards, visitor logs with host IPs, and most-visited endpoints.

---

## 2. GoSpider — Automated Reconnaissance

GoSpider is a fast web crawler for bug bounty recon. It discovers hidden endpoints, subdomains, parameters, AWS S3 bucket URLs, and JavaScript files.

### 2a. Basic Crawl

```bash
gospider -s "https://target.com" -o output_dir -c 10 -d 1
```

| Flag | Meaning |
|------|---------|
| `-s` | Target URL |
| `-o` | Output directory |
| `-c` | Concurrency (parallel threads) |
| `-d` | Crawl depth |

**Finds:** Subdomains, paths, JS files, S3 buckets, query parameters.

### 2b. JavaScript Analysis — LinkFinder Integration

GoSpider has LinkFinder built in [01:25]. It automatically parses JS files and extracts:
- API endpoints hardcoded in JS
- Internal routes
- Hidden paths not linked from HTML

### 2c. Clean Output Filtering

Pipe GoSpider output through `grep` to extract clean URLs:

```bash
# Clean absolute URLs
gospider -s "https://target.com" | grep -Eo '(http|https)://[^ ]+'
```

```bash
# Target only JavaScript files
gospider -s "https://target.com" | grep -E '\.js($|\?)'
```

### 2d. Passive Mode

```bash
gospider -s "https://target.com" --other-source --include-subs
```

**Why:** Queries external OSINT sources (Wayback CDX, AlienVault OTX) to find URLs no longer linked anywhere. Surfaces 404/403 endpoints that the active crawler can't access [01:49].

### 2e. Deep Crawl

```bash
gospider -s "https://target.com" -d 3 --other-source
```

`-d 3` = crawl up to 3 links deep. Reveals deeply nested paths like `/dashboard/admin/users/settings` [02:41].

### When to Use Each Mode

| Scenario | Command |
|----------|---------|
| Quick surface scan | `gospider -s "URL" -d 1` |
| Finding JS files | `gospider -s "URL" \| grep '\.js'` |
| Historical endpoints | `gospider -s "URL" --other-source` |
| Deep hidden content | `gospider -s "URL" -d 3 --other-source` |
| Full recon | `gospider -s "URL" -d 3 --other-source --include-subs` |

---

## 3. JavaScript Hunting & Secret Extraction

### 3a. Beautifying Minified JS

```bash
# Step 1: Find JS files
gospider -s "https://target.com" | grep -E '\.js($|\?)'

# Step 2: Open JS URL in browser
# Step 3: Use code formatter/beautifier extension
```

**Recommended extensions:** Pretty Beautiful (Chrome), JavaScript and CSS Code Beautifier.

After beautifying, look for:
- API endpoints (`/api/v1/users`, `/graphql`)
- Hardcoded API keys (`sk_live_...`, `AIza...`)
- Internal URLs (`internal.service.corp.com`)
- Sensitive comments (`// TODO: remove this debug key`)

### 3b. Automated Secret Scanning Pipeline

```bash
gospider -s "https://target.com" --other-source | grep -E '\.js($|\?)' | awk '{print $NF}' | nuclei -t exposure/tokens/
```

**Pipeline breakdown [04:15]:**

| Stage | Command | Purpose |
|-------|---------|---------|
| 1 | `gospider -s "URL" --other-source` | Crawl target + OSINT sources |
| 2 | `grep -E '\.js($|\?)'` | Filter to JS file URLs |
| 3 | `awk '{print $NF}'` | Extract the URL (last field) |
| 4 | `nuclei -t exposure/tokens/` | Scan for exposed tokens/secrets |

**Nuclei templates check for:** AWS keys, Google API keys, GitHub tokens, Slack tokens, Stripe keys, JWT tokens, private SSH keys, base64 credentials.

### 3c. Unfurl — URL Processing

```bash
# Extract unique domains
cat output_dir/* | unfurl -u domains | sort -u
```

```bash
# Extract unique paths
cat output_dir/* | unfurl -u paths | sort -u
```

**Why:** Cleans up thousands of URLs into unique subdomains and endpoints for targeted testing [03:59].

---

## 4. Specialized Tooling Extensions

### 4a. LazyEgg [04:26]

Parses recon data and extracts hidden domains and internal paths that goblin/spider tools might miss.

### 4b. FindSomething Browser Extension [04:44]

Dynamically monitors pages during browsing to catch:
- Hidden paths in page source
- Parameters from JavaScript blocks
- API endpoints in comments
- Sensitive data in the DOM

**GoSpider vs FindSomething:** GoSpider = offline automated scanning. FindSomething = live interactive scanning (finds dynamically loaded endpoints).

### 4c. Unfurl (see section 3c above)

---

## 5. Exploitation & Reporting (Pivoting)

Once you've discovered credentials, admin endpoints, and internal paths:

### The Pivot

```bash
# Example: Login with discovered creds
curl -c cookies.txt -X POST "https://target.com/admin/login" \
  -d "username=admin&password=leaked_password"

# Access admin endpoint with session
curl -b cookies.txt "https://target.com/admin/users/export"
```

### Testing for Stored XSS

1. Find input fields (user profiles, settings, comments) in authenticated areas
2. Inject payload: `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`
3. If the payload persists and executes for other users → **Stored XSS confirmed**

### Ethical Boundary

**Stop testing and document findings as soon as you achieve a high-impact PoC.** Do not keep digging once you have a clear finding — risk of causing damage or violating scope.

---

## 6. Complete Workflow (End-to-End)

```
Phase 1: Wayback Machine Recon
  └─ Check 404/403 pages for archived snapshots
  └─ Extract legacy endpoints, IPs, visitor data

Phase 2: GoSpider Crawling
  ├─ gospider -s "URL" -d 1              (quick surface scan)
  ├─ gospider -s "URL" --other-source     (passive OSINT)
  └─ gospider -s "URL" -d 3 --other-source (deep crawl)

Phase 3: JS Analysis
  ├─ Pipe GoSpider output → grep for .js files
  ├─ Beautify JS in browser
  └─ Pipeline: gospider | grep .js | awk | nuclei -t exposure/tokens/

Phase 4: Post-Processing
  ├─ Unfurl domains/paths from bulk output
  ├─ Run LazyEgg on recon data
  └─ Use FindSomething while browsing manually

Phase 5: Exploitation
  ├─ Pivot with discovered creds + admin paths
  ├─ Test for Stored XSS in authenticated areas
  └─ Document PoC → submit report
```

---

## 7. Command Reference

| # | Command | Purpose |
|---|---------|---------|
| 1 | `gospider -s "https://target.com" -o output_dir -c 10 -d 1` | Basic active crawl |
| 2 | `gospider -s "https://target.com" \| grep -Eo '(http\|https)://[^ ]+'` | Clean URL extraction |
| 3 | `gospider -s "https://target.com" \| grep -E '\.js($\|\?)'` | Isolate JS files |
| 4 | `gospider -s "https://target.com" --other-source --include-subs` | Passive OSINT scan |
| 5 | `gospider -s "https://target.com" -d 3 --other-source` | Deep crawl |
| 6 | `cat output_dir/* \| unfurl -u domains \| sort -u` | Extract unique subdomains |
| 7 | `cat output_dir/* \| unfurl -u paths \| sort -u` | Extract unique paths |
| 8 | `gospider -s "https://target.com" --other-source \| grep '\.js' \| awk '{print $NF}' \| nuclei -t exposure/tokens/` | JS secret scanning pipeline |

---

## ⚡ Golden Rule: Always Run Wayback CDX First

Before any active crawling, **always run the deduplicated Wayback CDX query**:

```bash
proxychains4 -q curl -s "https://web.archive.org/cdx/search/cdx?url=TARGET.COM/*&collapse=urlkey&output=text&fl=original" | sort -u > wayback_urls.txt
```

**Why this catches what everything else misses:**

| Method | Finds |
|--------|-------|
| Active crawl (GoSpider/Katana) | Only currently-linked pages |
| Passive scan (`--other-source`) | Limited OSINT sources |
| **Wayback CDX collapse=urlkey** | **Every URL that ever existed** — even deleted endpoints, old APIs, leaked configs |

**Pipeline for every hunt:**
```
Step 1: proxychains4 + Tor → Wayback CDX → get ALL unique URLs
Step 2: Filter out assets (.css, .js, .png) → focus on endpoints
Step 3: Test each unique endpoint against the live site
Step 4: Download all JS files referenced → scan for secrets
Step 5: Run active crawl (GoSpider/Katana) for remaining surface
```

**Indian Rail example:** Wayback CDX found **7 API endpoints** (`FetchAutoComplete`, `FetchRecaptchaKey`, `FetchTrainData`, `FetchQuota`, `CommonCaptcha`, etc.) that active crawling + passive scanning completely missed.

## 8. Key Takeaways

| Technique | Best For | Time Investment |
|-----------|----------|-----------------|
| Wayback Machine 404 bypass | Finding legacy endpoints & data | ~2 min per URL |
| GoSpider basic crawl | Surface mapping | 5-10 min |
| GoSpider passive mode | Historical endpoints | 5-10 min |
| GoSpider deep crawl | Hidden admin panels | 10-20 min |
| JS beautification + manual review | Finding secrets in context | 15-30 min |
| Pipeline: GoSpider → grep → nuclei | Automated secret scanning | 5 min (automated) |
| Unfurl processing | Cleaning up recon data | 2 min |
| LazyEgg | Extracting hidden domains | 2 min |
| FindSomething | Dynamic endpoint discovery | During manual testing |

---

https://www.youtube.com/watch?v=9Y8fuZagHfs
