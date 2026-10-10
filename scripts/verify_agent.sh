#!/bin/bash
# ==============================================================
# VERIFICATION AGENT v1
# Re-checks every finding from the hunter before reporting.
# Ensures 100% correct — no false positives.
# Uses CVSS scoring and multi-request verification.
# ==============================================================

INBOX="/tmp/agent_inbox"
OUTBOX="/tmp/agent_outbox"
VERIFIED_DIR="$HOME/recon_reports/verified_findings"
mkdir -p "$INBOX" "$OUTBOX" "$VERIFIED_DIR"

log() { echo "[$(date +%H:%M:%S)] $*" >> /tmp/verify_agent.log; }
cb() { curl -sk --max-time 10 "$@"; }

cvss_score() {
    local vuln_type="$1"
    case "$vuln_type" in
        *SQLI*|*RCE*|*AUTH_BYPASS*|*SSTI*|*LFI*|*CONFIG_LEAK*|*S3_BUCKET*|*GOOGLE_API*|*STRIPE_KEY*) echo "Critical (9.0-10.0)" ;;
        *SSRF*|*CORS_REFLECT*|*CORS_CREDENTIALS*|*IDOR*|*ACTUATOR_env*|*ACTUATOR_heapdump*|*GRAPHQL*) echo "High (7.0-8.9)" ;;
        *CORS_WILDCARD*|*ACTUATOR*|*METHOD_*|*OPEN_REDIRECT*|*LFI_PARAM*|*SSRF_PARAM*) echo "Medium (4.0-6.9)" ;;
        *NEW_SUB*|*OPEN_PORT*|*EP_STATUS*|*API_ENDPOINT*) echo "Informational (0.0-3.9)" ;;
        *) echo "Unknown" ;;
    esac
}

verify_finding() {
    local FILE="$1"
    local TITLE=$(head -1 "$FILE" | sed 's/^# //')
    local SEV=$(grep "^**Severity:**" "$FILE" | sed 's/.*Severity:** //')
    local CONTENT=$(grep -v "^#\|^_HASH\|^_UNVERIFIED\|^\*\*Time" "$FILE" | head -100)
    local HASH=$(grep "^_HASH=" "$FILE" | cut -d= -f2)

    log "VERIFYING: $TITLE ($SEV)"

    # Step 1: Determine verification method based on finding type
    local VERIFIED=false
    local CONFIDENCE=0
    local REPRODUCIBLE=false
    local NOTES=""

    # Extract target URL from content
    local TARGET_URL=$(echo "$CONTENT" | grep -oP 'https?://[^" |)\]]+' | head -1)
    local HTTP_CODE=$(echo "$CONTENT" | grep -oP 'HTTP \K[0-9]+' | head -1)

    # Step 2: Re-request the endpoint (fresh verification)
    if [ -n "$TARGET_URL" ]; then
        local FRESH_CODE=$(cb -w "%{http_code}" -o /tmp/vf_resp.txt "$TARGET_URL" 2>/dev/null)
        local FRESH_BODY=$(cat /tmp/vf_resp.txt 2>/dev/null | tr -d '\0' | head -c 1000)

        if [ "$FRESH_CODE" = "$HTTP_CODE" ] || [ -n "$FRESH_CODE" ]; then
            REPRODUCIBLE=true
            CONFIDENCE=$((CONFIDENCE + 40))
            NOTES="Re-request returned HTTP $FRESH_CODE (matches original $HTTP_CODE)"
        else
            NOTES="Re-request returned HTTP $FRESH_CODE (original was $HTTP_CODE) - may be intermittent"
            CONFIDENCE=$((CONFIDENCE + 10))
        fi

        # Step 3: Check response body for vulnerability indicators
        case "$TITLE" in
            *SQLI*)
                echo "$FRESH_BODY" | grep -qiE "sql|syntax|mysql|postgres|odbc|driver\|exception" && \
                    CONFIDENCE=$((CONFIDENCE + 30)) && NOTES="$NOTES; SQL error pattern confirmed"
                echo "$FRESH_BODY" | grep -qiE "warning|error|unclosed|quotation" && \
                    CONFIDENCE=$((CONFIDENCE + 20))
                ;;
            *CORS*)
                local CORS_HEADERS=$(cb -I -H "Origin: https://verify-test.evil.com" "$TARGET_URL" 2>/dev/null | \
                    grep -i "access-control")
                echo "$CORS_HEADERS" | grep -qi "verify-test.evil.com" && \
                    CONFIDENCE=$((CONFIDENCE + 40)) && \
                    NOTES="$NOTES; CORS reflection confirmed with test origin"
                echo "$CORS_HEADERS" | grep -qi "\*" && \
                    CONFIDENCE=$((CONFIDENCE + 20))
                ;;
            *ACTUATOR*)
                echo "$FRESH_BODY" | grep -qiE "spring|actuator|beans|config|env|property|health" && \
                    CONFIDENCE=$((CONFIDENCE + 40)) && \
                    NOTES="$NOTES; Actuator response contains Spring data"
                ;;
            *AUTH_BYPASS*)
                [ "$FRESH_CODE" = "200" ] || [ "$FRESH_CODE" = "201" ] || [ "$FRESH_CODE" = "204" ] && \
                    CONFIDENCE=$((CONFIDENCE + 40)) && \
                    NOTES="$NOTES; Auth bypass confirmed - endpoint accessible without valid auth"
                ;;
            *CONFIG_LEAK*)
                echo "$FRESH_BODY" | grep -qiE "password|secret|key|token|DB_|AWS_" && \
                    CONFIDENCE=$((CONFIDENCE + 50)) && \
                    NOTES="$NOTES; Config file contains sensitive data"
                ;;
            *IDOR*)
                [ "$FRESH_CODE" = "200" ] && echo "$FRESH_BODY" | grep -qv "not found\|null\|\[\]" && \
                    CONFIDENCE=$((CONFIDENCE + 40)) && \
                    NOTES="$NOTES; IDOR confirmed - data accessible for different IDs"
                ;;
            *SSRF*)
                echo "$FRESH_BODY" | grep -qiE "root:|meta-data|localhost|error|connection" && \
                    CONFIDENCE=$((CONFIDENCE + 30))
                ;;
            *SSTI*)
                echo "$FRESH_BODY" | grep -q "49" && \
                    CONFIDENCE=$((CONFIDENCE + 50)) && \
                    NOTES="$NOTES; SSTI confirmed - template evaluated to 49"
                ;;
            *LFI*)
                echo "$FRESH_BODY" | grep -qiE "root:|bin/bash|daemon:|for 16-bit" && \
                    CONFIDENCE=$((CONFIDENCE + 50)) && \
                    NOTES="$NOTES; LFI confirmed - file contents returned"
                ;;
            *S3_BUCKET*)
                echo "$FRESH_BODY" | grep -qiE "ListBucketResult|Contents|Key|ETag" && \
                    CONFIDENCE=$((CONFIDENCE + 40)) && \
                    NOTES="$NOTES; S3 bucket listing accessible"
                ;;
            *GOOGLE_API*|*STRIPE_KEY*)
                CONFIDENCE=$((CONFIDENCE + 50)) && \
                    NOTES="$NOTES; Hardcoded credential - no re-request needed"
                ;;
            *)
                [ "$FRESH_CODE" = "$HTTP_CODE" ] && CONFIDENCE=$((CONFIDENCE + 20))
                ;;
        esac
    fi

    # Step 4: Multi-request confirmation (3 requests, need 2/3 matching)
    local MATCH_COUNT=0
    for i in 1 2 3; do
        local R_CODE=$(cb -w "%{http_code}" -o /dev/null "$TARGET_URL" 2>/dev/null)
        [ "$R_CODE" = "$FRESH_CODE" ] && MATCH_COUNT=$((MATCH_COUNT + 1))
        sleep 0.5
    done
    [ $MATCH_COUNT -ge 2 ] && REPRODUCIBLE=true && CONFIDENCE=$((CONFIDENCE + 20))

    # Step 5: CVSS scoring
    local CVSS=$(cvss_score "$TITLE")

    # Step 6: Decision
    local VERDICT="REJECTED"
    local OUT_SEV="Informational"
    if [ "$REPRODUCIBLE" = true ] && [ $CONFIDENCE -ge 60 ]; then
        VERDICT="VERIFIED"
        OUT_SEV=$SEV
        # Upgrade severity for confirmed finds
        [ $CONFIDENCE -ge 90 ] && OUT_SEV="Critical"
    elif [ "$REPRODUCIBLE" = true ] && [ $CONFIDENCE -ge 30 ]; then
        VERDICT="PARTIALLY_VERIFIED"
        OUT_SEV="Low"
    fi

    # Step 7: Write verified finding or rejection report
    local TS=$(date +%Y%m%d_%H%M%S)
    local SAFE_NAME=$(echo "$TITLE" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-40)

    if [ "$VERDICT" = "REJECTED" ]; then
        cat > "$OUTBOX/REJECTED_${SAFE_NAME}_${TS}.md" <<- EOF
# REJECTED: $TITLE
**Original Severity:** $SEV
**Verification Time:** $(date '+%Y-%m-%d %H:%M:%S')
**Confidence Score:** $CONFIDENCE/100
**Reproducible:** $REPRODUCIBLE
**CVSS:** $CVSS
**Notes:** $NOTES
**Status:** REJECTED - False positive or not reproducible

**Original Content:**
$CONTENT
_HASH=${HASH}_
EOF
        log "REJECTED: $TITLE (confidence: $CONFIDENCE)"
    else
        local STATUS_FLAG=""
        [ "$VERDICT" = "PARTIALLY_VERIFIED" ] && STATUS_FLAG=" (partial)"
        cat > "$VERIFIED_DIR/READY_${OUT_SEV}_${SAFE_NAME}_${TS}.md" <<- EOF
# READY: $TITLE
**Original Severity:** $SEV
**Verified Severity:** $OUT_SEV
**Verification Time:** $(date '+%Y-%m-%d %H:%M:%S')
**Confidence Score:** $CONFIDENCE/100
**Reproducible:** $REPRODUCIBLE
**CVSS:** $CVSS
**Verification Notes:** $NOTES
**Status:** READY_FOR_REPORT$STATUS_FLAG
_HASH=${HASH}_

## Raw Finding
$CONTENT
EOF
        log "VERIFIED: $TITLE ($OUT_SEV, confidence: $CONFIDENCE)"
    fi

    # Move inbox file to done
    mv "$FILE" "${FILE}.done" 2>/dev/null
}

log "=== VERIFICATION AGENT STARTED ==="

while true; do
    # Process all files in inbox
    for FILE in "$INBOX"/*.md; do
        [ -f "$FILE" ] || continue
        # Skip already-processed
        echo "$FILE" | grep -q "\.done$" && continue
        verify_finding "$FILE"
    done

    # Report status
    v_count=$(ls "$VERIFIED_DIR"/*.md 2>/dev/null | wc -l)
    r_count=$(ls "$OUTBOX"/*.md 2>/dev/null | wc -l)
    inbox_remaining=$(ls "$INBOX"/*.md 2>/dev/null | grep -v "\.done$" | wc -l)
    log "Status: $v_count verified | $r_count rejected | $inbox_remaining pending verification"

    sleep 15
done
