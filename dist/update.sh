#!/usr/bin/env bash
# hydra update — pin & refresh the engine, zero config loss
set -e
echo "🐉 current engine: $(opencode --version 2>/dev/null || echo none)"
curl -fsSL https://opencode.ai/install -o /tmp/hydra_engine_install
echo "engine sha256: $(sha256sum /tmp/hydra_engine_install | cut -d' ' -f1)"
bash /tmp/hydra_engine_install && rm /tmp/hydra_engine_install
export PATH="$HOME/.opencode/bin:$PATH"
echo "🐉 updated → $(opencode --version)"
