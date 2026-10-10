#!/usr/bin/env python3
"""
Bug Bounty Coordination Client
Use this on both laptop and PC to share findings and coordinate.
"""

import json
import os
import sys
import time
from datetime import datetime
import urllib.request
import urllib.error

SERVER_URL = os.environ.get("COORD_SERVER", "http://127.0.0.1:5000")
INSTANCE_NAME = os.environ.get("INSTANCE_NAME", "laptop")

def api_call(method, path, data=None):
    """Make API call to coordination server."""
    url = f"{SERVER_URL}{path}"
    
    if data is not None:
        json_data = json.dumps(data).encode()
        req = urllib.request.Request(url, data=json_data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", f"CoordinationClient/1.0 ({INSTANCE_NAME})")
    else:
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", f"CoordinationClient/1.0 ({INSTANCE_NAME})")
    
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())
    except Exception as e:
        return {"error": str(e)}

def heartbeat(target="", findings_count=0, status="active"):
    """Register heartbeat for this instance."""
    return api_call("POST", "/heartbeat", {
        "name": INSTANCE_NAME,
        "status": status,
        "current_target": target,
        "findings_count": findings_count
    })

def share_finding(title, severity, target, endpoint, description, evidence=""):
    """Share a finding with the other instance."""
    return api_call("POST", "/share", {
        "title": title,
        "severity": severity,
        "target": target,
        "endpoint": endpoint,
        "description": description,
        "evidence": evidence,
        "instance": INSTANCE_NAME
    })

def claim_endpoint(endpoint, status="in_progress"):
    """Claim an endpoint so the other instance doesn't test it."""
    return api_call("POST", "/claim", {
        "endpoint": endpoint,
        "instance": INSTANCE_NAME,
        "status": status
    })

def release_endpoint(endpoint):
    """Release an endpoint when done."""
    return api_call("DELETE", f"/claim/{endpoint}")

def get_findings(since=None):
    """Get all findings (optionally since a timestamp)."""
    path = "/findings"
    if since:
        path += f"?since={since}"
    return api_call("GET", path)

def get_claimed():
    """Get all claimed endpoints."""
    return api_call("GET", "/claimed")

def get_instances():
    """Get active instances."""
    return api_call("GET", "/instances")

def get_status():
    """Get server status."""
    return api_call("GET", "/status")

def get_next_target(available_targets):
    """Suggest next unclaimed target."""
    return api_call("POST", "/next-target", {
        "available_targets": available_targets
    })

def update_progress(target, status, note=""):
    """Update progress on a target."""
    return api_call("POST", "/progress", {
        "target": target,
        "instance": INSTANCE_NAME,
        "status": status,
        "note": note
    })

def sync_all_findings(local_file):
    """Sync all local findings from a JSON file to the server."""
    if not os.path.exists(local_file):
        print(f"[!] Local findings file not found: {local_file}")
        return
    
    with open(local_file) as f:
        content = f.read()
    
    # Try to parse as JSON
    try:
        findings = json.loads(content)
        if isinstance(findings, list):
            for f in findings:
                result = share_finding(
                    title=f.get("title", "Unknown"),
                    severity=f.get("severity", "Info"),
                    target=f.get("target", ""),
                    endpoint=f.get("endpoint", ""),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", "")
                )
                print(f"  [{result.get('status', 'error')}] {f.get('title', 'Unknown')}")
    except json.JSONDecodeError:
        # Not JSON, try to parse FINDINGS.md format
        print("[*] Parsing FINDINGS.md format...")
        current = {}
        lines = content.split("\n")
        for line in lines:
            if line.startswith("### P"):
                if current.get("title"):
                    share_finding(
                        title=current["title"],
                        severity=current.get("severity", "Info"),
                        target=current.get("target", ""),
                        endpoint=current.get("endpoint", ""),
                        description=current.get("description", ""),
                        evidence=current.get("evidence", "")
                    )
                current = {"title": line.strip("# ")}
            elif line.startswith("- **Severity**:"):
                current["severity"] = line.split(":")[1].strip()
            elif line.startswith("- **Target**:"):
                current["target"] = line.split(":")[1].strip()
            elif line.startswith("- **Endpoint**:"):
                current["endpoint"] = line.split(":")[1].strip()
            elif line.startswith("- **Description**:"):
                current["description"] = line.split(":")[1].strip()
        if current.get("title"):
            share_finding(**current)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 coordinate.py <command> [args]")
        print("Commands:")
        print("  heartbeat                  Send heartbeat")
        print("  status                     Get server status")
        print("  findings                   List all findings")
        print("  instances                  List active instances")
        print("  share <title> <sev> <target> <endpoint> <desc>")
        print("  claim <endpoint>           Claim an endpoint")
        print("  release <endpoint>         Release an endpoint")
        print("  claimed                    List claimed endpoints")
        print("  sync <file>                Sync local findings to server")
        print("  next <target1,target2,...> Get next unclaimed target")
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "heartbeat":
        target = sys.argv[2] if len(sys.argv) > 2 else ""
        result = heartbeat(target=target)
        print(json.dumps(result, indent=2))
    
    elif cmd == "status":
        result = get_status()
        print(json.dumps(result, indent=2))
    
    elif cmd == "findings":
        result = get_findings()
        print(f"Total findings: {result.get('count', 0)}")
        for f in result.get("findings", []):
            print(f"  {f['id']}: [{f['severity']}] {f['title']} - {f['target']}")
    
    elif cmd == "instances":
        result = get_instances()
        print(f"Active instances: {result.get('active_count', 0)}")
        for name, info in result.get("instances", {}).items():
            print(f"  {name}: {info['current_target']} (last seen: {info['last_seen']})")
    
    elif cmd == "share":
        if len(sys.argv) < 7:
            print("Usage: share <title> <severity> <target> <endpoint> <description>")
            sys.exit(1)
        result = share_finding(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
        print(json.dumps(result, indent=2))
    
    elif cmd == "claim":
        if len(sys.argv) < 3:
            print("Usage: claim <endpoint>")
            sys.exit(1)
        result = claim_endpoint(sys.argv[2])
        print(json.dumps(result, indent=2))
    
    elif cmd == "release":
        if len(sys.argv) < 3:
            print("Usage: release <endpoint>")
            sys.exit(1)
        result = release_endpoint(sys.argv[2])
        print(json.dumps(result, indent=2))
    
    elif cmd == "claimed":
        result = get_claimed()
        print(f"Claimed endpoints: {len(result.get('claimed_endpoints', []))}")
        for c in result.get("claimed_endpoints", []):
            print(f"  {c['endpoint']} - by {c['claimed_by']} ({c['status']})")
    
    elif cmd == "sync":
        if len(sys.argv) < 3:
            print("Usage: sync <findings_file>")
            sys.exit(1)
        sync_all_findings(sys.argv[2])
    
    elif cmd == "next":
        if len(sys.argv) < 3:
            print("Usage: next <target1,target2,...>")
            sys.exit(1)
        targets = sys.argv[2].split(",")
        result = get_next_target(targets)
        print(json.dumps(result, indent=2))
    
    else:
        print(f"Unknown command: {cmd}")
