#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export HOME="$TMP"
mkdir -p "$HOME/.config/opencode"
printf '*.example.com\nonboarding-*.cloud.com\n' > "$HOME/.config/opencode/SCOPE_ALLOWLIST.txt"

check_allow() {
  if ! bash "$ROOT/scripts/scope_check.sh" "$1"; then
    echo "FAIL: expected allow: $1" >&2
    exit 1
  fi
}

check_deny() {
  if bash "$ROOT/scripts/scope_check.sh" "$1"; then
    echo "FAIL: expected deny: $1" >&2
    exit 1
  fi
}

check_allow app.example.com
check_deny notexample.com
check_deny example.com.evil.net
check_allow onboarding-prod.cloud.com
check_deny onboarding-prod.evil.cloud.com

echo "Scope shell policy tests passed."
