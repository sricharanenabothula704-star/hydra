# 🧠 Model Providers — HYDRA speaks 75+

HYDRA runs on **any** OpenAI-compatible model. opencode auto-discovers
providers when their env key is present — no config editing required.

## Quick-start (pick one)
```bash
export OPENROUTER_API_KEY=...   # 300+ models, one key
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
