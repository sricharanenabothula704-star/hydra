# 🧠 Model Providers — HYDRA speaks 75+

HYDRA leaves model selection to OpenCode by default. Use `/connect` to
authenticate with a provider and `/models` to inspect or select an available
model. Environment-key providers and local model servers are optional
alternatives.

## Default path: choose through OpenCode
```bash
opencode
# In the TUI: /connect, then /models
```

OpenCode Zen is a curated provider, but using its hosted models may require a
separate account/API key and paid credits. HYDRA does not require an OpenRouter
key for its default setup.

## Optional environment-key providers
```bash
export OPENROUTER_API_KEY=...   # optional alternative
export GROQ_API_KEY=...         # fastest free tier
export GEMINI_API_KEY=...       # generous free tier
ollama serve                    # 100% local & free
```

## Supported providers (set the env var, done)
openrouter · openai · anthropic · google/gemini · groq · mistral ·
deepseek · xai/grok · together · fireworks · cerebras · perplexity ·
cohere · azure · aws-bedrock · nvidia-nim · github-copilot · huggingface ·
ollama (local) · lmstudio (local) · vllm (local) · opencode-zen …

Check live status:  `./scripts/hydra_models.sh`

## Recommended for bug hunting
| Use | Provider/Model |
|---|---|
| Deep reasoning | `anthropic/claude-sonnet-4` |
| Long context recon dumps | `google/gemini-2.0-flash` |
| Fast cheap cycles (loop mode) | `groq/llama-3.3-70b` |
| Fully offline | `ollama/qwen2.5-coder:32b` |
