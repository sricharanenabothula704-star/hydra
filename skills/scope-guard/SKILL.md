---
name: scope-guard
description: >-
  MANDATORY Scope Enforcement Layer. Auto-loaded BEFORE any hunt begins.
  Prevents illegal out-of-scope testing. If SCOPE_ACTIVE.md is missing or
  the target is not in scope, ALL hunting is BLOCKED.
---

# ⛔ SCOPE GUARD — Mandatory Enforcement Layer

> **CRITICAL**: This skill MUST be loaded before ANY other skill in a hunt session.
> Testing out-of-scope targets is ILLEGAL (CFAA, Computer Misuse Act violations).
> This guard exists to prevent the AI from forgetting scope and committing violations.

---

## 0. THE HARD RULE

```
╔══════════════════════════════════════════════════════════════╗
║  NO RECON. NO SCANNING. NO EXPLOITATION.                    ║
║  WITHOUT A VALID SCOPE_ACTIVE.md FILE PRESENT.              ║
║                                                              ║
║  IF SCOPE_ACTIVE.md IS MISSING:                             ║
║    → STOP IMMEDIATELY                                       ║
║    → DO NOT START ANY HUNTING                               ║
║    → ASK THE USER: "What is the target scope?"              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 1. PHASE 0 — MANDATORY SCOPE CHECK (RUN FIRST)

**Before any `chaos`, `httpx`, `nuclei`, `ffuf`, or even `subfinder`:**

### Step 1: Check SCOPE_ACTIVE.md exists

```bash
if [ ! -f "$HOME/.opencode/skills/scope-guard/SCOPE_ACTIVE.md" ]; then
  echo "⛔ SCOPE GUARD: No SCOPE_ACTIVE.md found. Cannot start hunt."
  echo "→ Ask user: What program/target are we testing?"
  exit 1
fi
```

### Step 2: Read and verify scope

```bash
cat "$HOME/.opencode/skills/scope-guard/SCOPE_ACTIVE.md"
# Must contain: PROGRAM, TARGET_DOMAIN, IN_SCOPE list, OUT_OF_SCOPE list
```

### Step 3: Before every phase, verify target is in scope

For every domain/subdomain/IP before touching it:

```bash
is_in_scope() {
  local target="$1"
  local scope_file="$HOME/.opencode/skills/scope-guard/SCOPE_ACTIVE.md"

  # Extract in-scope patterns
  while IFS= read -r line; do
    # Check if target matches any in-scope pattern
    if [[ "$target" == *"$line"* ]]; then
      return 0
    fi
  done < <(grep -E '^\s*-\s+\*\.' "$scope_file" | sed 's/^\s*-\s\+\*\.//' | sed 's/\*//g')

  return 1  # Not in scope
}
```

### Step 4: If ANY result is out of scope → LOG AND STOP

```bash
log_and_block() {
  local target="$1"
  local reason="$2"
  echo "⛔ BLOCKED: $target — $reason"
  echo "$(date '+%Y-%m-%d %H:%M:%S') | BLOCKED | $target | $reason" >> "$HOME/.opencode/skills/scope-guard/SCOPE_VIOLATIONS.log"
}

# Call this before ANY request to a domain/IP
if ! is_in_scope "$domain"; then
  log_and_block "$domain" "Not in scope"
  echo "⛔ SCOPE VIOLATION: STOPPING. This target is not authorized."
  exit 1
fi
```

---

## 2. SCOPE_ACTIVE.md FORMAT

This file MUST be written at session start BEFORE any hunting:

```markdown
# ACTIVE SCOPE — DO NOT MODIFY DURING SESSION
# Generated: 2026-07-20

## Program
- Name: <Program Name>
- Platform: <BugBase/HackerOne/Bugcrowd/Other>
- Reporter: <Your Username>

## In-Scope (exact matches)
### Domains
- *.target.com
- api.target.com
- app.target.com

### IP Ranges (if any)
- REDACTED_INTERNAL_IP/24

### Mobile Apps (if any)
- com.target.app (Android)
- com.target.ios (iOS)

## Out-of-Scope (explicitly excluded)
- *.admin.target.com
- *.internal.target.com
- third-party-services.com

## Rules & Restrictions
- No DoS/DDoS
- No social engineering
- No physical access
- Use test accounts only: test@example.com / TestPass123
- Max rate: 10 req/sec

## Session Safety
- [ ] Scope verified with user
- [ ] Test accounts ready
- [ ] No OOS assets in any command
```

---

## 3. PHASE-CHECK HOOKS

Every phase must call scope guard before executing:

### Before Recon Phase
```bash
echo "⛔ SCOPE CHECK: Recon phase"
grep -c "Scope verified" "$HOME/.opencode/skills/scope-guard/SCOPE_ACTIVE.md" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "⛔ SCOPE NOT VERIFIED. Cannot start recon."
  exit 1
fi
```

### Before Each Subdomain/URL Probe
```python
def check_scope(target: str, scope_file: str) -> bool:
    """Hard scope check — blocks OOS targets before any request."""
    with open(scope_file) as f:
        content = f.read()

    # Extract in-scope patterns
    in_scope = re.findall(r'\*\.([a-zA-Z0-9.-]+)', content)

    for pattern in in_scope:
        if pattern in target:
            return True

    return False
```

### Before Port Scan
```bash
# Check all IP resolution targets are in scope
for ip in $(cat ip.txt); do
  domain=$(dig +noall +answer -x "$ip" 2>/dev/null | head -1 | awk '{print $NF}' | sed 's/\.$//')
  if ! is_in_scope "$domain"; then
    log_and_block "$ip" "Resolved to OOS domain: $domain"
    exit 1
  fi
done
```

### Before Exploitation
```bash
echo "⛔ SCOPE CHECK: Exploitation phase"
grep -q "Rules & Restrictions" "$HOME/.opencode/skills/scope-guard/SCOPE_ACTIVE.md"
if [ $? -ne 0 ]; then
  echo "⛔ Cannot find rules. Exploitation BLOCKED."
  exit 1
fi
```

---

## 4. SCOPE VIOLATION LOG

All violations are logged to `SCOPE_VIOLATIONS.log`:

```
2026-07-20 14:30:01 | BLOCKED | admin.other-company.com | Resolved from subdomain scan
2026-07-20 14:30:05 | BLOCKED | REDACTED_INTERNAL_IP | Private IP, not in scope
2026-07-20 14:31:00 | BLOCKED | api.target.com/actuator | Actuator path, requires auth check first
```

If this log grows, the session is WASTING TIME on OOS targets — STOP and re-scope.

---

## 5. EMERGENCY STOP

If at any point the agent detects it is testing an OOS target:

```bash
echo "⛔⛔⛔ EMERGENCY STOP ⛔⛔⛔"
echo "Target: $target is OUT OF SCOPE"
echo "Action: Stopping all testing immediately."
echo "Log: Appending to SCOPE_VIOLATIONS.log"
echo "Advice: Inform user. Do NOT continue with any phase."
exit 1
```

---

## 6. TRUST MODEL ENFORCEMENT

This skill is the **hard gate** for the entire hack skills system:

```
user says "hunt x.com"
  → scope-guard checks SCOPE_ACTIVE.md
    → MISSING → STOP, ask user for scope
    → NEEDS UPDATE → STOP, ask user to update
    → VALID → ALLOW: continue to recon-and-methodology
      → recon finds y.com
        → scope-guard checks: is y.com in scope?
          → NO → BLOCK, log violation
          → YES → ALLOW: continue with scan
```

---

## 7. AGENT MEMORY PERSISTENCE

Every agent (Hunter, Recon, Verifier, Reporter) MUST read this at session start:

```bash
cat "$HOME/.opencode/skills/scope-guard/SCOPE_ACTIVE.md"
```

If it doesn't exist, agents must NOT propose, recommend, or execute any security testing action.

---

## 8. QUICK REFERENCE

| Situation | Action |
|-----------|--------|
| No SCOPE_ACTIVE.md | STOP. Ask user for scope. |
| Target not in in-scope list | BLOCK. Log violation. |
| Target matches out-of-scope list | BLOCK. Log violation. |
| IP resolves to OOS domain | BLOCK. Log violation. |
| Discovery leads to OOS subdomain | STOP that path. Do NOT follow. |
| User changes scope mid-session | Regenerate SCOPE_ACTIVE.md before continuing. |
| Test accounts not confirmed | BLOCK exploitation. Ask for credentials. |
| Rate limits not confirmed | BLOCK scanning. Ask for limits. |

---

## 9. SCOPE IS LAW

```
                     ╔══════════════════════╗
                     ║  SCOPE IS THE LAW    ║
                     ║                      ║
                     ║  OOS = ILLEGAL       ║
                     ║  OOS = WASTED TIME    ║
                     ║  OOS = BANNED         ║
                     ║                      ║
                     ║  CHECK. EVERY. TARGET.║
                     ╚══════════════════════╝
```
