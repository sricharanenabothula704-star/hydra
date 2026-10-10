#!/usr/bin/env python3
"""HYDRA index builder — regenerates skills/index.json from SKILL.md frontmatter.

Run after adding/updating any skill module. Produces the machine-readable
index the agents (and the website) use for routing and browsing.

Usage: python3 skills_build_index.py [repo_root]
"""
import json, re, sys
from pathlib import Path

CATS = {
    "web": ["xss","sqli","ssrf","ssti","xxe","csrf","cors","crlf","clickjack","redirect","cache","smuggl","http","graphql","websocket","prototype","nosql","orm","csp","dangling","csv","host-header","parameter","upload","path-traversal","file-access","jwt","oauth","api-","idor","auth","session"],
    "forensics-defense": ["forensic","incident","malware","threat-hunt","detect","log-","monitoring","compliance","canary","honeypot","memory-forensics","volatility","pcap","traffic-analysis","steganography"],
    "platform": ["linux","windows","macos","active-directory","kubernetes","container","ntlm","lateral","privilege","unauthorized-access","tunneling","network-protocol","kerberos","dpapi","mimikatz"],
    "ai": ["llm","ai-red-teaming","prompt-injection","promptfoo","agentic-mcp","guardrails","garak","pyrit"],
    "recon": ["recon","dns","subdomain","bug-bounty","scope","insecure-source","js-analysis"],
    "binary": ["heap","stack","format-string","arbitrary-write","kernel","browser-exploit","vm-and-bytecode","symbolic","anti-debug","code-obfuscat","binary-protection","sandbox","reverse-shell"],
    "crypto": ["rsa","lattice","symmetric","hash","classical","type-juggling","encrypt"],
    "mobile": ["android","ios","mobile"],
}

def categorize(name):
    n = name.lower()
    for cat, keys in CATS.items():
        if any(k in n for k in keys):
            return cat
    return "other"

def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent)
    skills_dir = root / "skills"
    index = {"version": 4, "generated": __import__("datetime").date.today().isoformat(), "skills": []}

    for d in sorted(skills_dir.iterdir()):
        if not d.is_dir():
            continue
        entry = {"name": d.name,
                 "files": sorted(x.name for x in d.iterdir() if x.is_file())}
        sm = d / "SKILL.md"
        if sm.exists():
            t = sm.read_text(errors="ignore")
            m = re.search(r'^description:\s*>-\s*\n((?:\s{2,}.*\n?)+)', t, re.M)
            desc = " ".join(l.strip() for l in m.group(1).splitlines()) if m else ""
            if not desc:
                m2 = re.search(r'^description:\s*(.+)$', t, re.M)
                desc = m2.group(1).strip() if m2 else ""
            entry["description"] = desc[:280]
            v = re.search(r"^version:\s*['\"]?([^'\"\n]+)", t, re.M)
            if v: entry["version"] = v.group(1).strip()
            tags = re.findall(r'^-\s*(.+)$', t[t.find("tags:"):t.find("tags:")+400], re.M) if "tags:" in t else []
            if tags: entry["tags"] = tags[:8]
            entry["category"] = categorize(d.name)
        index["skills"].append(entry)

    summary = {}
    for s in index["skills"]:
        summary[s.get("category", "other")] = summary.get(s.get("category", "other"), 0) + 1
    index["summary"] = dict(sorted(summary.items(), key=lambda x: -x[1]))
    index["total"] = len(index["skills"])

    out = skills_dir / "index.json"
    out.write_text(json.dumps(index, indent=2))
    print(f"[OK] {index['total']} modules indexed → {out}")
    print(json.dumps(index["summary"], indent=2))

if __name__ == "__main__":
    main()
