# 🧪 Reviewer Kit — how to collect real reviews for HYDRA

## Golden rule
One honest critical review beats ten "cool project!" replies. Ask specific questions.

---

## 1. Where to share (ranked by signal)

| Channel | Why | Angle |
|---|---|---|
| **r/bugbounty** | Your exact audience | "I built this, tear it apart" |
| **Show HN** (news.ycombinator.com) | Deep technical audience | Focus on verifier-gate design |
| **opencode Discord/GitHub** | Users who already have the runtime | "I built 7 agents on your runtime" |
| **X/Twitter** #bugbounty | Fast reach | Short thread + demo clip |
| **BugBase Discord** | Already prepared post in `~/hydra-promo-kit.md` | Community-first tone |
| **r/netsec** (moderated) | Only after eval suite exists — they'll demand proof | Skip until tests ship |

## 2. Copy-paste outreach message

> Hi! I open-sourced HYDRA — an AI agent system for bug bounty
> (7 agents: hunter → verifier → reporter pipeline, 989 skill modules,
> built on opencode).
>
> I'm not selling anything — MIT licensed, no catch.
>
> I'm looking for **critical reviews**, not praise:
> - Where would this workflow break down?
> - Is the verifier's 3-request/confidence gate sound?
> - What's missing that you'd demand before trusting it?
>
> Repo: https://github.com/sricharan996/hydra
> Site: https://sricharan996.github.io
>
> If you write up thoughts (even 5 bullet points), I'll feature them in the
> README's reviews section — critical takes especially.

## 3. Make leaving a review frictionless

This repo now has a structured feedback template (`.github/ISSUE_TEMPLATE/feedback.yml`).
Every review lands as an issue → easy to quote → link back.

## 4. Turning reviews into README content

1. Get permission: *"mind if I quote this in the README?"*
2. Add verbatim quotes (keep criticism!) to the site's Reviews section
3. Always show the scorecard including low scores — credibility compounds
