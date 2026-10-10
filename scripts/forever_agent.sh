#!/bin/bash
# Forever-running agent bootstrapper
# This script ensures the agent is ALWAYS running
# It runs in an infinite loop and restarts the agent immediately if it dies

AGENT_SCRIPT="/tmp/agent.py"
PID_FILE="/tmp/agent_pid"
PORT=9199

mkdir -p /tmp/agent_logs

while true; do
    # Check if agent is alive and responding
    ALIVE=0
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            if curl -sf --max-time 3 "http://127.0.0.1:$PORT/status" >/dev/null 2>&1; then
                ALIVE=1
            fi
        fi
    fi

    if [ "$ALIVE" -eq 0 ]; then
        echo "[$(date)] Agent DOWN. Restarting..." >> /tmp/agent_logs/watchdog.log
        kill -9 $(cat "$PID_FILE" 2>/dev/null) $(lsof -ti:$PORT 2>/dev/null) 2>/dev/null
        sleep 2
        python3 -u "$AGENT_SCRIPT" &
        NEW_PID=$!
        echo $NEW_PID > "$PID_FILE"
        echo "[$(date)] Restarted with PID $NEW_PID" >> /tmp/agent_logs/watchdog.log
        sleep 5
    fi

    sleep 30
done
