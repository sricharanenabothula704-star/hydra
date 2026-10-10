#!/bin/bash
# ==============================================================
# AI BUG BOUNTY AGENT SYSTEM - MASTER LAUNCHER
# Launches all 3 agents as background processes.
# Architecture:
#   my_hunter_agent.sh       →  Continuous recon + probing (bring your own)
#   verify_agent.sh          →  Verifies each finding (re-checks, confirms)
#   report_agent.sh          →  Generates BugBase-format reports
# ==============================================================

BASE="$HOME"
# Add your own target-specific hunter script (see docs/CUSTOMIZE.md)
AGENTS=(
    # "$BASE/my_hunter_agent.sh"
    "$BASE/verify_agent.sh"
    "$BASE/report_agent.sh"
)

mkdir -p /tmp/agent_inbox /tmp/agent_outbox
mkdir -p "$BASE/recon_reports/verified_findings"
mkdir -p "$BASE/recon_reports/bugbase_reports"

echo "============================================"
echo "  AI BUG BOUNTY AGENT SYSTEM v3"
echo "  Launching 3 agents..."
echo "============================================"

PIDS=""
for AGENT in "${AGENTS[@]}"; do
    if [ -f "$AGENT" ] && [ -x "$AGENT" ]; then
        NAME=$(basename "$AGENT")
        bash "$AGENT" &
        PID=$!
        PIDS="$PIDS $PID"
        echo "  [OK] $NAME → PID $PID"
    else
        echo "  [!!] $AGENT not found or not executable"
    fi
done

echo ""
echo "============================================"
echo "  Pipeline:"
echo "    Hunter (methods)"
echo "      ↓ (raw findings → /tmp/agent_inbox)"
echo "    Verification Agent (re-checks + confirms)"
echo "      ↓ (verified → recon_reports/verified_findings/)"
echo "    Report Agent (BugBase template)"
echo "      ↓ (reports → recon_reports/bugbase_reports/)"
echo "============================================"
echo ""
echo "PIDs: $PIDS"
echo "Monitor: tail -f /tmp/my_hunter.log /tmp/verify_agent.log /tmp/report_agent.log"
echo ""
echo "Press Ctrl+C to stop all agents."

trap "echo 'Stopping all agents...'; kill $PIDS 2>/dev/null; exit 0" SIGINT SIGTERM

wait
