#!/usr/bin/env bash
# hydra_models.sh — show every AI provider HYDRA can use RIGHT NOW,
# based on the API keys present in your environment. Zero config needed:
# opencode auto-discovers providers whose env keys are set.
#
# usage:
#   ./hydra_models.sh            # status of all supported providers
#   ./hydra_models.sh --ready    # only the ones ready to use
set -uo pipefail

G=$'\033[32m'; R=$'\033[90m'; X=$'\033[0m'; B=$'\033[1m'

# provider_id | env_key | example model
PROVIDERS=(
  "openrouter|OPENROUTER_API_KEY|moonshotai/kimi-k2"
  "openai|OPENAI_API_KEY|gpt-4o"
  "anthropic|ANTHROPIC_API_KEY|claude-sonnet-4-20250514"
  "google|GEMINI_API_KEY|gemini-2.0-flash"
  "groq|GROQ_API_KEY|llama-3.3-70b-versatile"
  "mistral|MISTRAL_API_KEY|mistral-large-latest"
  "deepseek|DEEPSEEK_API_KEY|deepseek-chat"
  "xai|XAI_API_KEY|grok-3"
  "together|TOGETHER_API_KEY|meta-llama/Llama-3.3-70B-Instruct-Turbo"
  "fireworks|FIREWORKS_API_KEY|accounts/fireworks/models/llama-v3p3-70b-instruct"
  "cerebras|CEREBRAS_API_KEY|llama-3.3-70b"
  "perplexity|PERPLEXITY_API_KEY|sonar-pro"
  "cohere|COHERE_API_KEY|command-r-plus"
  "azure|AZURE_API_KEY|your-deployment"
  "aws-bedrock|AWS_ACCESS_KEY_ID|anthropic.claude-3-5-sonnet"
  "nvidia-nim|NVIDIA_NIM_API_KEY|moonshotai/kimi-k2"
  "github-copilot|GITHUB_TOKEN|gpt-4o"
  "voyage|VOYAGE_API_KEY|voyage-3"
  "huggingface|HF_TOKEN|meta-llama/Llama-3.3-70B-Instruct"
  "ollama|OLLAMA_HOST|llama3.3 (local)"
  "lmstudio|LMSTUDIO|any-local-model"
  "vllm|VLLM_BASE_URL|any-served-model"
  "opencode-zen|OPENCODE_API_KEY|agent-first coding models"
)

READY=0; TOTAL=0
printf "${B}🐉 HYDRA model providers${X}\n"
printf "%-18s %-28s %s\n" "PROVIDER" "ENV KEY" "STATUS"
printf -- "--------------------------------------------------------------\n"
for row in "${PROVIDERS[@]}"; do
  IFS='|' read -r id key model <<< "$row"; TOTAL=$((TOTAL+1))
  if [ -n "${!key:-}" ]; then READY=$((READY+1)); printf "${G}%-18s %-28s ● READY${X}\n" "$id" "$key"
  else [ "${1:-}" != "--ready" ] && printf "${R}%-18s %-28s ○ set %s${X}\n" "$id" "$key" "$key"; fi
done
printf -- "--------------------------------------------------------------\n"
printf "ready: ${G}%s${X} / %s providers · 300+ models via openrouter alone\n" "$READY" "$TOTAL"
[ "$READY" -gt 0 ] && printf "\nuse in opencode.jsonc:  \"model\": \"<provider>/<model>\"\n"
exit 0
