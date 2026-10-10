#!/usr/bin/env bash
# run_meta.sh — emit reproducibility metadata for every finding/report
# usage: ./run_meta.sh > run_meta.json      (or pipe into finding files)
set -uo pipefail
ver(){ command -v "$1" >/dev/null && "$1" --version 2>/dev/null | head -1 || echo "not-installed"; }
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RUN_ID="HYDRA-$(date +%Y%m%d)-$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat <<EOF
{
  "run_id": "$RUN_ID",
  "timestamp_utc": "$TS",
  "hydra": "$(cd "$(dirname "$0")/.." && git describe --tags 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "opencode": "$(ver opencode)",
  "httpx": "$(ver httpx)", "naabu": "$(ver naabu)", "nuclei": "$(ver nuclei)",
  "nuclei_templates": "$(ls -d ~/nuclei-templates 2>/dev/null >/dev/null && cd ~/nuclei-templates && git rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "model_provider": "${OPENROUTER_API_KEY:+openrouter}${NVIDIA_NIM_API_KEY:+nvidia-nim}",
  "host": "$(uname -sr)"
}
EOF
