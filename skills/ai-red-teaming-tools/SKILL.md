---
name: ai-red-teaming-tools
description: >-
  LLM red-teaming playbook with garak and PyRIT. Use when testing AI systems for prompt injection, jailbreaks, data leakage, hallucination classes, or model abuse — automated probing harness setup, probe selection, result triage, and reporting.
---

# SKILL: AI Red-Teaming Tools — garak & PyRIT

> **AI LOAD INSTRUCTION**: Operational workflows for automated LLM security assessment. Covers harness setup (garak, PyRIT), probe taxonomy, execution against local or API models, result interpretation, false-positive filtering, and report structure. For authorized AI-system assessments only.

## 1. WHEN TO USE THIS

- Client asks for "AI/LLM pentest" of their chatbot, copilot, or RAG pipeline
- Bug bounty programs covering AI features (increasingly common)
- Pre-deployment hardening of your own agent stack (including HYDRA itself)

## 2. HARNESS SETUP

### garak (probe-based scanner)
```bash
pip install garak
# list available probes
garak --list_probes | grep -E "dan|injection|leak|divergence"
# run a targeted scan against an OpenAI-compatible endpoint
garak --model_type openai --model_name <model-id> \
      --generator_option_file endpoint.json \
      --probes encoding.InjectBase64,dan.Dan_11_0,lmrc.Anthropomorphisation \
      --report_prefix hydragarak
```

### PyRIT (Microsoft's risk-it framework — orchestration-heavy)
```bash
pip install pyrit
# use for multi-turn attack chains: Crescendo, TAP,PAIR-style loops
```
Choose **garak** for breadth (300+ probes), **PyRIT** for depth (adaptive multi-turn escalation).

## 3. PROBE TAXONOMY — what to actually test

| Class | Goal | Example probes |
|---|---|---|
| Prompt injection | Override system instructions | direct/indirect injection, context switching |
| Jailbreak | Bypass safety alignment | DAN variants, cipher/payload splitting, crescendo |
| Data leakage | Extract system prompt / training data | system-prompt extraction, PII probes |
| Harmful content | Elicit prohibited outputs | misuse, harm benchmarks |
| Hallucination & misinformation | False confidence | lmrc suite, factual anchors |
| Agentic abuse | Tool/API misuse via model | tool-exfil, indirect injection via retrieved docs |

## 4. METHODOLOGY

1. **Scope the model surface**: chat endpoint? RAG sources? tools/plugins? system prompt visible?
2. **Baseline**: record normal responses to benign prompts (needed for diffing)
3. **Run breadth pass** (garak) → collect failures
4. **Escalate winners manually**: turn single-shot bypasses into multi-turn chains (Crescendo pattern)
5. **Test indirect injection**: poison documents the target retrieves (email, web page, ticket) — usually higher impact than direct attacks
6. **Triage**: dedupe by root cause (one filter bypass ≠ ten findings)
7. **Rate-limit respect**: AI endpoints are expensive; cap concurrency, stop on 429 storms

## 5. TRIAGE & FALSE POSITIVES

- A refusal that leaks *partial* harmful content still counts if actionable
- Check refusals under different phrasings — inconsistent enforcement = finding
- Log exact request/response pairs; AI outputs are non-deterministic → capture evidence every time

## 6. REPORT STRUCTURE

```
Finding: <attack class> — <one-line>
Severity: based on real policy impact, not shock value
Evidence: full conversation transcript (sanitized)
Repro rate: X/N attempts succeeded
Root cause hypothesis: missing input filter / weak system prompt / tool trust boundary
Fix: guardrail layer + regression test suggestion
```

## 7. DEFENSES TO RECOMMEND

Input/output guardrails (see `llm-guardrails-eval` skill), instruction-hierarchy enforcement, tool-permission least privilege, retrieval content sandboxing, logging + anomaly detection on token patterns.

## REFERENCES
- garak: github.com/leondz/garak · PyRIT: github.com/Azure/PyRIT
- OWASP LLM Top 10 · Related skills: `llm-prompt-injection`, `llm-guardrails-eval`, `agentic-mcp-security`
