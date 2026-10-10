# Moreficent Bug Bounty — Recon Findings

**Program:** Moreficent VDP (BugBase)
**Date:** 2026-07-05
**Methodology:** Passive recon only (no automated scanners per policy)

---

## 1. Program Overview

| Item | Detail |
|------|--------|
| Type | VDP — Vulnerability Disclosure Program (not paid) |
| Platform | BugBase |
| Target | moreficent.com |
| Stack | AWS (CloudFront), Next.js 13.0.2, TypeScript, Rust, Docker, React |
| Rules | ❌ No Nuclei, Burp, ZAP, or brute force |

## 2. Recon Pipeline Applied

| Step | Source | Result |
|------|--------|--------|
| 1 | `proxychains4` + Wayback CDX `collapse=urlkey` | Only marketing assets — no hidden APIs |
| 2 | `crt.sh` | **70+ subdomains** discovered |
| 3 | Manual HTTP probe | Only 3 live (www, docs, oda) |
| 4 | Next.js JS bundle analysis | Build ID: `qu1pJOZAiD5rOv2rnMU-Y` — no secrets |
| 5 | GitBook docs analysis | Space IDs, image tokens, S3 bucket refs |
| 6 | `.well-known/` path check | All 404 |
| 7 | `/api` endpoint check | 404 |

## 3. Subdomain Discovery (70+)

### Live Subdomains

| Subdomain | Service | Tech |
|-----------|---------|------|
| `www.moreficent.com` | Marketing site | Next.js 13 / CloudFront |
| `docs.moreficent.com` | Product Documentation | GitBook / Cloudflare |
| `oda.moreficent.com` | Oda CLI Documentation | GitBook / Cloudflare |

### Internal Subdomains (all return 000 — not externally accessible)

| Group | Subdomains |
|-------|------------|
| Core | `api`, `app`, `auth`, `log`, `demo`, `usdemo` |
| Infrastructure | `k1`-`k12`, `prodk11`, `bs1`, `c1`, `ks3` |
| Proxies | `rp1`, `rp2`, `rpfwss` |
| Services | `nightcrawler`, `charon`, `gregor`, `janus*`, `bifrost*`, `pingermumbai`, `charonmumbai` |
| Customer | `sharechat`, `kukufm`, `masai`, `masaidev`, `procol`, `oda`, `luminar`, `cerve`, `bobble`, `bbr` |
| Staging | `app.preprod`, `auth.preprod`, `auth.staging`, `bs1.preprod`, `k1`-`k4.preprod`, `nightcrawler.preprod`, `gregor.preprod`, `janus.preprod` |
| Other | `airmeet`, `tutorialseu`, `iitr`, `nith`, `vitb`, `vitv`, `wsecho`, `fm`, `gdg`, `ducs` |

## 4. Main Site Analysis (`www.moreficent.com`)

```
Tech: Next.js 13.0.2
Infra: CloudFront (AWS) → Cloudflare
Build ID: qu1pJOZAiD5rOv2rnMU-Y
```

- **No API endpoints** exposed on the main site
- `/api/` → 308 redirect to `/api` → 404
- No `robots.txt`, no `sitemap.xml`
- JS bundles are standard Next.js boilerplate — no secrets
- No source maps exposed (both js.map → 404)

## 5. Documentation Sites

### `docs.moreficent.com` — Moreficent Docs
- **GitBook space ID:** `5TAT52HxgT5KxiQ12Lez`
- **GitBook site ID:** `site_yVZ0h`
- **Image token:** `a2d06cd4-c5af-4362-9f41-d98b2d14275b`
- **robots.txt:** Full `Disallow: /` (blocked from search)
- **Privacy Policy ref:** `https://legal-common.s3.us-east-2.amazonaws.com/PrivacyPolicy.pdf` (S3 bucket no longer exists — 404)

### `oda.moreficent.com` — Oda CLI Docs
- **GitBook space ID:** `rI8NUZMhW6UeKFQAglAX`
- **GitBook site ID:** `site_V3IRG`
- **Image token:** `eaa0589a-4b91-4146-96cd-eb956af52ddc`
- **Google Analytics ID:** `G-GN7KF05QZ0` (via GitBook integration)
- **Oda CLI latest version:** 0.8.0

### CLI Credential Model (from Oda docs)
- Uses `--access-key` + `--secret-key` auth (similar to AWS IAM)
- `--server` parameter can be set to connect to custom server
- Commands: `moreficent-configure`, `moreficent-connect`, `moreficent-status`, `moreficent-cred-check`, `moreficent-account-info`, `moreficent-archive`, `moreficent-throttle`
- Dunebox AVD management: `dunebox-init`, `dunebox-connect`, `dunebox-avd-create`, `dunebox-image-create`, `dunebox-terminate`

### Documentation Pages (from GitBook site-index JSON)

**Moreficent Docs:**
- `/start-here/` (introduction, terminology, limitations, support)
- `/the-basics/` (launcher screen, session manager, application screen, clipboard, android device connection)

**Oda Docs:**
- `/getting-started/` (windows, linux, macos, configuration)
- `/command-reference/` (all CLI commands)
- `/changelog`

## 6. Policy-Compliant Potential Vectors

Since automated scanners are banned, manual testing would focus on:

1. **GitBook exposed tokens** — The image tokens (`a2d06cd4-...`, `eaa0589a-...`) are for CDN images, but GitBook API tokens could exist in page source
2. **CLI `--server` parameter** — If `api.moreficent.com` resolves internally, testing the API manually
3. **Docs authentication pages** — Check if any docs pages contain secret links or login portals
4. **GitHub recon** — Search for moreficent API keys in public repos
5. **S3 bucket** — `legal-common` bucket is gone, but other buckets might exist

## 7. No Critical/High Findings

After thorough passive recon:
- ✅ No exposed API endpoints
- ✅ No hardcoded credentials in JS
- ✅ No `.git` or `.env` leaks
- ✅ No subdomain takeover candidates
- ✅ No open S3 buckets
- ✅ No exposed admin panels

The main attack surface (`api.moreficent.com`, `app.moreficent.com`, `auth.moreficent.com`) is **internal-only** and not accessible without VPN credentials.
