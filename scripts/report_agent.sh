#!/bin/bash
# ==============================================================
# BUGBASE REPORT GENERATOR AGENT v1
# Takes verified findings and generates BugBase-format reports.
# Template matches BugBase submission format exactly.
# ==============================================================

VERIFIED_DIR="$HOME/recon_reports/verified_findings"
REPORTS_DIR="$HOME/recon_reports/bugbase_reports"
mkdir -p "$REPORTS_DIR"

log() { echo "[$(date +%H:%M:%S)] $*" >> /tmp/report_agent.log; }

# Default values (user-configured)
TESTING_EMAIL="${REPORTER_EMAIL:-you@example.com}"
REPORTER_NAME="${REPORTER_NAME:-YOUR_HANDLE}"

generate_bugbase_report() {
    local FILE="$1"
    local TITLE=$(head -1 "$FILE" | sed 's/^# READY: //')
    local SEV=$(grep "^**Verified Severity:**" "$FILE" | sed 's/.*Severity:** //')
    local ORIG_SEV=$(grep "^**Original Severity:**" "$FILE" | sed 's/.*Severity:** //')
    local CVSS=$(grep "^**CVSS:**" "$FILE" | sed 's/.*CVSS:** //')
    local NOTES=$(grep "^**Verification Notes:**" "$FILE" | sed 's/.*Notes:** //')
    local RAW=$(sed -n '/^## Raw Finding/,$p' "$FILE" | tail -n +2 | head -200)
    local HASH=$(grep "^_HASH=" "$FILE" | cut -d= -f2)

    # Extract target URL and HTTP details from raw finding
    local TARGET_URL=$(echo "$RAW" | grep -oP 'https?://[^" |)\]]+' | head -3 | tr '\n' ' ')
    local HTTP_CODE=$(echo "$RAW" | grep -oP 'HTTP \K[0-9]+' | head -1)
    local RESPONSE_BODY=$(echo "$RAW" | sed 's/.*| //' | head -5 | tr '\n' ' ')

    # Map severity to BugBase severity picker
    local BUGBASE_SEV="Informational"
    case "$SEV" in
        *Critical*) BUGBASE_SEV="Critical" ;;
        *High*) BUGBASE_SEV="High" ;;
        *Medium*) BUGBASE_SEV="Medium" ;;
        *Low*) BUGBASE_SEV="Low" ;;
        *) BUGBASE_SEV="Informational" ;;
    esac

    # Map title to vulnerability type
    local VULN_TYPE="Other"
    case "$TITLE" in
        *SQLI*) VULN_TYPE="SQL Injection" ;;
        *SSTI*) VULN_TYPE="Server-Side Template Injection" ;;
        *SSRF*) VULN_TYPE="Server-Side Request Forgery (SSRF)" ;;
        *CORS_REFLECT*|*CORS_WILDCARD*|*CORS_CREDENTIALS*) VULN_TYPE="CORS Misconfiguration" ;;
        *AUTH_BYPASS*) VULN_TYPE="Authentication Bypass" ;;
        *IDOR*) VULN_TYPE="Insecure Direct Object Reference (IDOR)" ;;
        *LFI*) VULN_TYPE="Local File Inclusion (LFI)" ;;
        *CONFIG_LEAK*) VULN_TYPE="Sensitive Data Exposure" ;;
        *ACTUATOR_env*|*ACTUATOR_heapdump*) VULN_TYPE="Sensitive Data Exposure" ;;
        *ACTUATOR*) VULN_TYPE="Information Disclosure" ;;
        *S3_BUCKET*) VULN_TYPE="Security Misconfiguration" ;;
        *GOOGLE_API*|*STRIPE_KEY*) VULN_TYPE="Exposed Secret / API Key" ;;
        *OPEN_REDIRECT*) VULN_TYPE="Open Redirect" ;;
        *METHOD_*) VULN_TYPE="HTTP Method Misconfiguration" ;;
        *GRAPHQL*) VULN_TYPE="GraphQL Information Disclosure" ;;
        *NEW_SUB*) VULN_TYPE="Information Disclosure" ;;
        *) VULN_TYPE="Security Misconfiguration" ;;
    esac

    # Determine scope
    local SCOPE=""
    # >>> EDIT: map your own program domains to scope names here <<<
    if echo "$TARGET_URL" | grep -qi "example.com"; then
        SCOPE="Example Responsible Disclosure Program"
    else
        SCOPE="General"
    fi

    # Build description based on vulnerability type
    local DESCRIPTION=""
    local SECURITY_IMPACT=""
    local REPRO_STEPS=""
    local RECOMMENDATIONS=""

    case "$VULN_TYPE" in
        "SQL Injection")
            DESCRIPTION="A SQL Injection vulnerability was identified at the endpoint. The application fails to properly sanitize user-supplied input before including it in SQL queries, allowing an attacker to manipulate database queries."
            SECURITY_IMPACT="An attacker can extract, modify, or delete sensitive data from the database, including user credentials, PII, and business-critical records. In some cases, this can lead to RCE or full database compromise."
            REPRO_STEPS="1. Identify the vulnerable parameter\n2. Inject SQL payload: '\n3. Observe error message revealing database structure\n4. Use sqlmap to extract data: sqlmap -u '$TARGET_URL' --batch --dump"
            RECOMMENDATIONS="Use parameterized queries / prepared statements. Implement input validation and an allowlist approach. Use a WAF as defense-in-depth."
            ;;
        "Authentication Bypass")
            DESCRIPTION="The endpoint accepts requests without proper authentication. By manipulating HTTP headers or omitting auth tokens, an unauthenticated attacker can access protected resources."
            SECURITY_IMPACT="Attackers can access sensitive internal APIs, extract customer PII, perform privileged operations, and compromise user accounts without any authentication."
            REPRO_STEPS="1. Send request without auth headers: curl -X POST '$TARGET_URL' -H 'Content-Type: application/json' -d '{}'\n2. Observe HTTP $HTTP_CODE response with data\n3. Repeat with different bypass headers to confirm"
            RECOMMENDATIONS="Implement proper authentication checks on all endpoints. Use a centralized auth middleware. Never trust client-side headers for authorization."
            ;;
        "CORS Misconfiguration")
            DESCRIPTION="The server reflects arbitrary origins in the Access-Control-Allow-Origin header and/or allows credentials, enabling cross-origin data theft."
            SECURITY_IMPACT="An attacker can craft a malicious webpage that makes authenticated requests to this API, reading sensitive responses. Combined with Access-Control-Allow-Credentials: true, this enables full account takeover."
            REPRO_STEPS="1. Send preflight request: curl -I -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: GET' $TARGET_URL\n2. Confirm origin reflection in response\n3. Create PoC HTML page that exfiltrates data"
            RECOMMENDATIONS="Do not reflect arbitrary origins. Use an allowlist of trusted origins. Avoid combining wildcard origins with Access-Control-Allow-Credentials: true."
            ;;
        "Server-Side Request Forgery (SSRF)")
            DESCRIPTION="The application accepts user-supplied URLs and makes requests to them from the server, enabling SSRF attacks against internal infrastructure."
            SECURITY_IMPACT="An attacker can probe internal networks, access cloud metadata endpoints (169.254.169.254), interact with internal services, and potentially achieve RCE."
            REPRO_STEPS="1. Submit URL pointing to internal service\n2. Observe response reflecting internal data\n3. Access cloud metadata endpoint to extract AWS credentials"
            RECOMMENDATIONS="Implement an allowlist of permitted URLs/domains. Block private IP ranges. Use a URL parser that prevents protocol smuggling."
            ;;
        "Sensitive Data Exposure")
            DESCRIPTION="Sensitive configuration files, environment variables, or backup files are accessible without authentication, exposing secrets and internal infrastructure details."
            SECURITY_IMPACT="Exposed credentials can lead to full infrastructure compromise. Database dumps expose all customer PII. API keys enable unauthorized service usage at the company's expense."
            REPRO_STEPS="1. Access the exposed URL: curl -s '$TARGET_URL'\n2. Review the response for secrets, credentials, or sensitive data\n3. Verify the data can be used to access protected resources"
            RECOMMENDATIONS="Restrict access to sensitive files. Remove backup/config files from public web roots. Use environment variables only - never hardcode secrets."
            ;;
        "Server-Side Template Injection (SSTI)")
            DESCRIPTION="User input is evaluated by a server-side template engine without proper sanitization, allowing injection of template directives."
            SECURITY_IMPACT="SSTI can lead to RCE, data exfiltration, and full server compromise. Attackers can execute arbitrary system commands on the server."
            REPRO_STEPS="1. Inject template payload: {{7*7}}\n2. Observe '49' in response (template evaluation)\n3. Escalate to RCE using framework-specific payloads"
            RECOMMENDATIONS="Never allow user input in template expressions. Use a sandboxed template engine. Apply contextual output encoding."
            ;;
        "Insecure Direct Object Reference (IDOR)")
            DESCRIPTION="The application exposes direct object references (sequential IDs) without proper authorization checks, allowing access to other users' data."
            SECURITY_IMPACT="Attackers can enumerate IDs to access, modify, or delete other users' private data. This includes PII, financial records, and account details."
            REPRO_STEPS="1. Authenticate and note your resource ID\n2. Change the ID to adjacent values (ID-1, ID+1)\n3. Observe other users' data returned without authorization"
            RECOMMENDATIONS="Use indirect object references (UUIDs). Implement proper authorization checks for every resource access. Use relationship-based access control."
            ;;
        "Exposed Secret / API Key")
            DESCRIPTION="Hardcoded API keys or secrets were found in client-side JavaScript files or publicly accessible configuration files."
            SECURITY_IMPACT="Stolen API keys can be used to access paid services (Gemini, Stripe, AWS) at the company's expense. Sensitive operations may be performed using these keys."
            REPRO_STEPS="1. Extract the exposed key from the source\n2. Validate the key is active: curl -s 'https://generativelanguage.googleapis.com/v1/models?key=KEY'\n3. Demonstrate unauthorized usage"
            RECOMMENDATIONS="Never hardcode secrets in client-side code. Use environment variables and server-side proxies. Rotate exposed keys immediately."
            ;;
        "GraphQL Information Disclosure")
            DESCRIPTION="GraphQL introspection is enabled on the production endpoint, exposing the entire schema including queries, mutations, and potentially hidden/private fields."
            SECURITY_IMPACT="Attackers can discover all available data types, fields, and mutations, including admin-only operations. This enables targeted attacks on the API."
            REPRO_STEPS="1. Send introspection query to GraphQL endpoint: {\"query\":\"{__schema{types{name}}}\"}\n2. Analyze the returned schema for sensitive types\n3. Query exposed fields for data extraction"
            RECOMMENDATIONS="Disable introspection in production. Implement query depth limiting and rate limiting. Use authentication for all GraphQL endpoints."
            ;;
        "Local File Inclusion (LFI)")
            DESCRIPTION="User-controlled path parameters are used to read files from the filesystem without proper validation, enabling LFI attacks."
            SECURITY_IMPACT="Attackers can read arbitrary files (/etc/passwd, application source code, database configs). Combined with file upload, this can lead to RCE."
            REPRO_STEPS="1. Inject path traversal: curl -s '$TARGET_URL'\n2. Confirm file contents in response\n3. Read additional sensitive files to escalate"
            RECOMMENDATIONS="Use an allowlist of permitted files. Validate and sanitize all file paths. Use a mapping layer instead of direct filesystem access."
            ;;
        "Security Misconfiguration")
            DESCRIPTION="A security misconfiguration exposes internal infrastructure details or allows unintended access to resources."
            SECURITY_IMPACT="Depends on the specific misconfiguration - may include data exposure, access to internal tools, or infrastructure compromise."
            REPRO_STEPS="1. Access the identified endpoint: curl -s '$TARGET_URL'\n2. Document the exposed information\n3. Verify impact on security posture"
            RECOMMENDATIONS="Review security configuration. Implement the principle of least privilege. Regular security audits."
            ;;
        *)
            DESCRIPTION="A security vulnerability was identified. Please refer to the technical details below."
            SECURITY_IMPACT="Please assess based on the specific vulnerability details."
            REPRO_STEPS="1. Access: $TARGET_URL\n2. Review the response\n3. Document findings"
            RECOMMENDATIONS="Implement security best practices based on the identified vulnerability type."
            ;;
    esac

    # Generate the BugBase-format report
    local TS=$(date +%Y%m%d_%H%M%S)
    local SAFE_TITLE=$(echo "$TITLE" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-40)

    cat > "$REPORTS_DIR/BUGBASE_${BUGBASE_SEV}_${SAFE_TITLE}_${TS}.md" <<- REPORTEOF
# BugBase Report: ${TITLE}

## Dashboard Metadata
- **Program:** ${SCOPE}
- **Reported By:** ${REPORTER_NAME}
- **Testing Email:** ${TESTING_EMAIL}
- **Date:** $(date '+%Y-%m-%d %H:%M:%S')
- **BugBase Template:** BugBase Standard Report
- _HASH=${HASH}_

---

## Submit Report

### Select Your Scope
**Scope:** ${SCOPE}

### Vulnerable Endpoint / Affected URL
${TARGET_URL}

### Select Your Vulnerability Type
**Type:** ${VULN_TYPE}

### Select Severity
**Severity:** ${BUGBASE_SEV}
**CVSS:** ${CVSS}

---

## Your Report

### Report Title
${TITLE}

### Report Summary
${DESCRIPTION}

### Security Impact
${SECURITY_IMPACT}

### Proof of Concept

\`\`\`
Endpoint: ${TARGET_URL}
HTTP Status: ${HTTP_CODE}
Raw Response: ${RESPONSE_BODY}

Verification Notes: ${NOTES}
\`\`\`

---

## Report Submission Template

### Description:
${DESCRIPTION}

### Security Impact
${SECURITY_IMPACT}

### Steps To Reproduce:
${REPRO_STEPS}

### Specifics
- **Testing Account:** ${TESTING_EMAIL}
- **Affected Domain(s):** ${TARGET_URL}
- **Specific Versions/Vendors:** N/A

### Recommendations
${RECOMMENDATIONS}

---

## Vulnerability Impact
- **IP Address:** Detected via endpoint
- **Testing Email:** ${TESTING_EMAIL}

---

## Review And Submit Your Report

### Report Title
${TITLE}

### Report Scope
${SCOPE}

### Vulnerability Type
${VULN_TYPE}

### Severity
${BUGBASE_SEV}

### Report Summary
${DESCRIPTION}

### Vulnerability Impact
${SECURITY_IMPACT}

---

## Auto-generated from verified finding
## Confidence: Verified by verification agent
## Ready for manual review and submission
REPORTEOF

    log "REPORT GENERATED: $TITLE ($BUGBASE_SEV)"
}

log "=== REPORT GENERATOR AGENT STARTED ==="

while true; do
    for FILE in "$VERIFIED_DIR"/*.md; do
        [ -f "$FILE" ] || continue
        # Skip already-processed
        echo "$FILE" | grep -q "\.reported$" && continue
        
        # Check if this is a verified finding (contains READY: tag)
        head -1 "$FILE" | grep -q "^# READY:" || continue
        
        generate_bugbase_report "$FILE"
        mv "$FILE" "${FILE}.reported" 2>/dev/null
    done

    r_count=$(ls "$REPORTS_DIR"/*.md 2>/dev/null | wc -l)
    pending_count=$(ls "$VERIFIED_DIR"/*.md 2>/dev/null | grep -v "\.reported$" | wc -l)
    log "Status: $r_count reports generated | $pending_count pending report generation"

    sleep 15
done
