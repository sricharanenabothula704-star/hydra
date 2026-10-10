#!/bin/bash
# Auto-restart watchdog for the unified discovery agent
# Designed to be run via cron every minute

AGENT_PID_FILE="/tmp/agent_pid"
AGENT_LOG="/tmp/agent_py.log"
HTTP_PORT=9199

# Check if agent is running and responding
agent_alive() {
    if [ ! -f "$AGENT_PID_FILE" ]; then
        return 1
    fi
    local PID=$(cat "$AGENT_PID_FILE")
    if ! kill -0 "$PID" 2>/dev/null; then
        return 1
    fi
    # Check HTTP endpoint
    curl -sf --max-time 3 "http://127.0.0.1:$HTTP_PORT/status" >/dev/null 2>&1
    return $?
}

start_agent() {
    echo "[$(date)] Starting unified agent..." >> "$AGENT_LOG"
    nohup python3 -u /tmp/agent.py >> "$AGENT_LOG" 2>&1 &
    local PID=$!
    echo $PID > "$AGENT_PID_FILE"
    sleep 3
    if kill -0 $PID 2>/dev/null; then
        echo "[$(date)] Agent started with PID $PID" >> "$AGENT_LOG"
    else
        echo "[$(date)] FAILED to start agent" >> "$AGENT_LOG"
    fi
}

# Main watchdog logic
if ! agent_alive; then
    echo "[$(date)] Agent not responding. Restarting..." >> "$AGENT_LOG"
    kill -9 $(cat "$AGENT_PID_FILE" 2>/dev/null) 2>/dev/null
    kill -9 $(lsof -ti:$HTTP_PORT 2>/dev/null) 2>/dev/null
    sleep 1
    start_agent
fi

# Ensure findings directory exists
mkdir -p /home/user/recon_reports/unreported
mkdir -p /tmp/agent_inbox /tmp/agent_outbox /tmp/agent_processed /tmp/agent_logs
