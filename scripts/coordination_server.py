#!/usr/bin/env python3
"""
Bug Bounty Coordination Server
Allows two opencode instances (laptop + PC) to share findings,
coordinate targets, and avoid duplicate work in real-time.
"""

import json
import os
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# Storage file
STORAGE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "coordination_db.json")

def load_db():
    if os.path.exists(STORAGE_FILE):
        with open(STORAGE_FILE) as f:
            return json.load(f)
    return {
        "findings": [],
        "targets": {},
        "instances": {},
        "claimed_endpoints": [],
        "stats": {
            "total_findings": 0,
            "instances_seen": set()
        }
    }

def save_db(db):
    # Convert set to list for JSON serialization
    db_copy = json.loads(json.dumps(db))
    if "stats" in db_copy and "instances_seen" in db_copy["stats"]:
        db_copy["stats"]["instances_seen"] = list(db_copy["stats"]["instances_seen"])
    with open(STORAGE_FILE, "w") as f:
        json.dump(db_copy, f, indent=2)

# Auto-save every 30 seconds
def auto_save():
    while True:
        time.sleep(30)
        db = load_db()
        save_db(db)

threading.Thread(target=auto_save, daemon=True).start()

@app.route("/")
def index():
    return jsonify({
        "service": "Bug Bounty Coordination Server",
        "endpoints": {
            "POST /share": "Share a new finding",
            "GET /findings": "Get all findings (optional ?since=<timestamp>)",
            "GET /findings/<id>": "Get specific finding",
            "POST /claim": "Claim a target/endpoint to avoid duplication",
            "GET /claimed": "Get all claimed endpoints",
            "POST /heartbeat": "Instance heartbeat (name, status, current_target)",
            "GET /instances": "Get all active instances",
            "GET /status": "Get server status & stats",
            "GET /next-target": "Suggest next unclaimed target",
            "POST /progress": "Update progress on a target"
        },
        "server_time": datetime.utcnow().isoformat()
    })

@app.route("/share", methods=["POST"])
def share_finding():
    """Share a new finding. Deduplicates by title."""
    data = request.get_json()
    if not data or "title" not in data:
        return jsonify({"error": "Missing required field: title"}), 400
    
    db = load_db()
    
    # Check for duplicates
    for existing in db["findings"]:
        if existing["title"] == data["title"]:
            return jsonify({"status": "duplicate", "message": "Finding already exists"}), 200
    
    finding = {
        "id": f"F-{len(db['findings'])+1:04d}",
        "title": data["title"],
        "severity": data.get("severity", "Unknown"),
        "target": data.get("target", ""),
        "endpoint": data.get("endpoint", ""),
        "description": data.get("description", ""),
        "remediation": data.get("remediation", ""),
        "evidence": data.get("evidence", ""),
        "discovered_by": data.get("instance", "unknown"),
        "timestamp": datetime.utcnow().isoformat()
    }
    
    db["findings"].append(finding)
    db["stats"]["total_findings"] = len(db["findings"])
    save_db(db)
    
    return jsonify({"status": "saved", "finding": finding}), 201

@app.route("/findings", methods=["GET"])
def get_findings():
    """Get all findings. Optional ?since=<ISO timestamp> for incremental sync."""
    db = load_db()
    since = request.args.get("since")
    
    if since:
        filtered = [f for f in db["findings"] if f.get("timestamp", "") > since]
        return jsonify({"findings": filtered, "count": len(filtered)})
    
    return jsonify({"findings": db["findings"], "count": len(db["findings"])})

@app.route("/findings/<finding_id>", methods=["GET"])
def get_finding(finding_id):
    db = load_db()
    for f in db["findings"]:
        if f["id"] == finding_id:
            return jsonify(f)
    return jsonify({"error": "Finding not found"}), 404

@app.route("/claim", methods=["POST"])
def claim_endpoint():
    """Claim an endpoint/target so the other instance doesn't test it."""
    data = request.get_json()
    if not data or "endpoint" not in data:
        return jsonify({"error": "Missing required field: endpoint"}), 400
    
    db = load_db()
    endpoint = data["endpoint"]
    instance = data.get("instance", "unknown")
    
    # Check if already claimed
    for claimed in db["claimed_endpoints"]:
        if claimed["endpoint"] == endpoint:
            return jsonify({
                "status": "already_claimed",
                "claimed_by": claimed["claimed_by"],
                "claimed_at": claimed["timestamp"]
            }), 200
    
    claim = {
        "endpoint": endpoint,
        "claimed_by": instance,
        "timestamp": datetime.utcnow().isoformat(),
        "status": data.get("status", "in_progress")
    }
    
    db["claimed_endpoints"].append(claim)
    save_db(db)
    
    return jsonify({"status": "claimed", "claim": claim}), 201

@app.route("/claim/<endpoint>", methods=["DELETE"])
def release_claim(endpoint):
    """Release a claim when done testing."""
    db = load_db()
    original_count = len(db["claimed_endpoints"])
    db["claimed_endpoints"] = [c for c in db["claimed_endpoints"] if c["endpoint"] != endpoint]
    
    if len(db["claimed_endpoints"]) < original_count:
        save_db(db)
        return jsonify({"status": "released"})
    return jsonify({"status": "not_found"}), 404

@app.route("/claimed", methods=["GET"])
def get_claimed():
    db = load_db()
    return jsonify({"claimed_endpoints": db["claimed_endpoints"]})

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    """Register or update an instance."""
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"error": "Missing required field: name"}), 400
    
    db = load_db()
    name = data["name"]
    
    db["instances"][name] = {
        "last_seen": datetime.utcnow().isoformat(),
        "status": data.get("status", "active"),
        "current_target": data.get("current_target", ""),
        "findings_count": data.get("findings_count", 0),
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", "")
    }
    
    if "stats" not in db:
        db["stats"] = {"instances_seen": set()}
    db["stats"]["instances_seen"] = list(set(list(db["stats"].get("instances_seen", [])) + [name]))
    
    save_db(db)
    return jsonify({"status": "ok", "instance": name})

@app.route("/instances", methods=["GET"])
def get_instances():
    db = load_db()
    # Filter out stale instances (> 5 min)
    now = datetime.utcnow()
    active = {}
    for name, info in db.get("instances", {}).items():
        last = datetime.fromisoformat(info["last_seen"])
        if (now - last).total_seconds() < 300:
            active[name] = info
    return jsonify({"instances": active, "active_count": len(active)})

@app.route("/status")
def get_status():
    db = load_db()
    now = datetime.utcnow()
    
    # Count active instances
    active_count = 0
    for info in db.get("instances", {}).values():
        last = datetime.fromisoformat(info["last_seen"])
        if (now - last).total_seconds() < 300:
            active_count += 1
    
    return jsonify({
        "findings_count": len(db["findings"]),
        "claimed_endpoints": len(db["claimed_endpoints"]),
        "active_instances": active_count,
        "total_instances_seen": len(db.get("stats", {}).get("instances_seen", [])),
        "server_time": datetime.utcnow().isoformat()
    })

@app.route("/next-target", methods=["POST"])
def suggest_next_target():
    """Suggest the next unclaimed target from a list provided in the request body."""
    data = request.get_json()
    if not data or "available_targets" not in data:
        return jsonify({"error": "Missing required field: available_targets"}), 400
    
    db = load_db()
    claimed_endpoints = {c["endpoint"] for c in db["claimed_endpoints"]}
    
    # Find unclaimed targets
    unclaimed = [t for t in data["available_targets"] if t not in claimed_endpoints]
    
    if not unclaimed:
        # All targets claimed - suggest re-scan of oldest claimed
        oldest = min(db["claimed_endpoints"], key=lambda c: c["timestamp"])
        return jsonify({
            "status": "all_claimed",
            "suggestion": oldest["endpoint"],
            "note": f"All targets claimed. Oldest claim was on {oldest['endpoint']} by {oldest['claimed_by']}"
        })
    
    return jsonify({
        "status": "available",
        "suggestion": unclaimed[0],
        "remaining": len(unclaimed)
    })

@app.route("/progress", methods=["POST"])
def update_progress():
    """Update progress on a specific target."""
    data = request.get_json()
    if not data or "target" not in data:
        return jsonify({"error": "Missing required field: target"}), 400
    
    db = load_db()
    
    progress_entry = {
        "target": data["target"],
        "instance": data.get("instance", "unknown"),
        "status": data.get("status", "in_progress"),
        "note": data.get("note", ""),
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if "progress_log" not in db:
        db["progress_log"] = []
    db["progress_log"].append(progress_entry)
    
    # Keep last 1000 entries
    if len(db["progress_log"]) > 1000:
        db["progress_log"] = db["progress_log"][-1000:]
    
    save_db(db)
    return jsonify({"status": "logged", "entry": progress_entry})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] Coordination Server starting on {host}:{port}")
    print(f"[*] Storage file: {STORAGE_FILE}")
    print(f"[*] Share this URL with your other instance:")
    print(f"    http://100.115.92.204:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
