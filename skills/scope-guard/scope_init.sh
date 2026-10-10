#!/bin/bash
# ============================================================
# SCOPE INIT — Run this BEFORE any bug hunting session
# Auto-generates SCOPE_ACTIVE.md and enforces scope rules
# ============================================================

SCOPE_DIR="$HOME/.opencode/skills/scope-guard"
SCOPE_FILE="$SCOPE_DIR/SCOPE_ACTIVE.md"
VIOLATIONS_LOG="$SCOPE_DIR/SCOPE_VIOLATIONS.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}╔═══════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║     SCOPE GUARD — Session Initializer     ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════╝${NC}"

# Check if SCOPE_ACTIVE.md already exists and is fresh (< 12 hours)
if [ -f "$SCOPE_FILE" ]; then
    FILE_AGE=$(( $(date +%s) - $(stat -c %Y "$SCOPE_FILE") ))
    if [ $FILE_AGE -lt 43200 ]; then
        echo -e "${GREEN}[✓] SCOPE_ACTIVE.md exists and is fresh ($((FILE_AGE / 3600))h old)${NC}"
        echo -e "${GREEN}[✓] Active Scope:${NC}"
        grep -E "^- Name:|^- \*\.|^- " "$SCOPE_FILE" | head -10
        echo ""
        echo -n "Use existing scope? [Y/n]: "
        read -r use_existing
        if [[ "$use_existing" =~ ^[Yy]?$ ]]; then
            echo -e "${GREEN}[✓] Using existing scope. Session safe to start.${NC}"
            exit 0
        fi
    else
        echo -e "${YELLOW}[!] SCOPE_ACTIVE.md is older than 12 hours. Regenerating...${NC}"
    fi
fi

echo ""
echo "=== SCOPE SETUP ==="
echo ""

# Gather scope info
echo -n "Program name: "
read -r program_name

echo -n "Platform (BugBase/HackerOne/Bugcrowd/Other): "
read -r platform

echo -n "Your reporter username: "
read -r username

echo -n "Target domain (e.g., *.target.com): "
read -r target_domain

echo -n "IP ranges (comma-separated, or 'none'): "
read -r ip_ranges

echo -n "Mobile apps (comma-separated, or 'none'): "
read -r mobile_apps

echo -n "Excluded domains (comma-separated, or 'none'): "
read -r excluded

echo -n "Special rules/restrictions: "
read -r rules

echo -n "Test accounts available? (y/n): "
read -r has_accounts

# Generate SCOPE_ACTIVE.md
DATE=$(date '+%Y-%m-%d %H:%M:%S')

cat > "$SCOPE_FILE" << EOF
# ACTIVE SCOPE — DO NOT MODIFY DURING SESSION
# Generated: $DATE

## Program
- Name: $program_name
- Platform: $platform
- Reporter: $username

## In-Scope (exact matches)
### Domains
- $target_domain

### IP Ranges (if any)
- ${ip_ranges:-none}

### Mobile Apps (if any)
- ${mobile_apps:-none}

## Out-of-Scope (explicitly excluded)
- ${excluded:-none}

## Rules & Restrictions
- $rules

## Session Safety
- [ ] Scope verified with user
EOF

if [[ "$has_accounts" == "y" ]]; then
    echo "- [ ] Test accounts ready" >> "$SCOPE_FILE"
fi

echo "- [ ] No OOS assets in any command" >> "$SCOPE_FILE"

echo ""
echo -e "${GREEN}[✓] SCOPE_ACTIVE.md generated at: $SCOPE_FILE${NC}"
echo ""
echo -e "${YELLOW}=== Session Scope Summary ===${NC}"
cat "$SCOPE_FILE"
echo ""

# Verify user confirms
echo -n "Confirm scope is correct and ready to hunt? (y/N): "
read -r confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "${RED}[✗] Scope not confirmed. Exiting.${NC}"
    echo "Run this script again when scope is ready."
    rm -f "$SCOPE_FILE"
    exit 1
fi

# Mark as verified
sed -i 's/- \[ \] Scope verified with user/- [x] Scope verified with user/' "$SCOPE_FILE"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     SCOPE VERIFIED. SAFE TO HUNT.        ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo "REMEMBER: Every target must match an in-scope pattern."
echo "If a subdomain resolves to an OOS domain — BLOCK IT."
echo ""

# Clear old violation log
> "$VIOLATIONS_LOG"
echo "Violations log cleared: $VIOLATIONS_LOG"
