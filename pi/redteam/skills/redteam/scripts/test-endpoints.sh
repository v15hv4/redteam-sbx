#!/bin/bash
# API Endpoint Testing Script
# Tests all discovered endpoints with multiple HTTP methods
# Produces a table format like Terrain's security assessment

TARGET="${1:-api.example.com}"
AUTH_TOKEN="${2:-}"
OUTPUT_DIR="${3:-/tmp/redteam-endpoints}"
ENDPOINTS_FILE="${4:-endpoints.txt}"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "=== API Endpoint Testing for $TARGET ==="
echo ""

# ============================================================
# Default Endpoints to Test
# ============================================================
cat > default-endpoints.txt << 'EOF'
# User/Account endpoints
/user
/users
/users/
/user/me
/user/profile
/user_dashboard/users
/user_dashboard/users/
/user_dashboard/users/1
/user_dashboard/users/1/
/user_dashboard/logs
/user_dashboard/logs/
/user_dashboard/usage
/user_dashboard/usage/
/user_dashboard/rotate_token
/user_dashboard/notification_emails

# Authentication
/auth
/auth/login
/auth/logout
/auth/signup
/auth/register
/auth/forgot
/auth/reset
/auth/verify
/auth/token
/auth/refresh
/auth0/login
/auth0/signup
/auth0/update_primary_email
/authentication/userinfo

# Billing/Payments
/billing
/billing/invoices
/billing/usage
/payments
/payments/purchase
/payments/purchases
/payments/packages
/tenants/payments/purchase
/tenants/payments/purchases
/tenants/payments/packages
/stripe/webhook
/stripe/checkout

# Admin
/admin
/admin/
/admin/login
/admin/users
/admin/settings
/admin/config
/internal
/internal/users
/internal/config

# API Core
/api
/api/v1
/api/v2
/v1
/v2
/graphql
/graphql/

# Search/Data
/search
/query
/filter
/export
/import
/batch
/batch/

# Person/Company (common data APIs)
/person/search
/person/enrich
/person/search/autocomplete
/company/search
/company/enrich
/company/search/autocomplete
/company/identify
/screener/company
/screener/company/
/screener/company/search
/screener/person/search
/screener/screen
/screener/linkedin_posts
/screener/persondb/autocomplete
/screener/companydb/autocomplete
/screener/identify

# Jobs
/job/search
/jobs

# Web/Live
/web/search/live
/web/enrich/live
/professional_network/search/autocomplete

# Integrations
/slack/webhook
/tenants/slack/webhook
/webhook
/webhooks
/callback
/oauth
/oauth/callback

# Config/Status
/health
/healthz
/health/live
/health/ready
/status
/status/
/metrics
/debug
/config
/settings
/.well-known/openid-configuration
/.well-known/jwks.json

# Documentation
/docs
/swagger
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/redoc
EOF

# Use provided endpoints file or default
if [ -f "$ENDPOINTS_FILE" ]; then
    cat "$ENDPOINTS_FILE" >> all-endpoints.txt
fi
cat default-endpoints.txt >> all-endpoints.txt
sort -u all-endpoints.txt | grep -v "^#" | grep -v "^$" > endpoints-to-test.txt

# ============================================================
# HTTP Methods to Test
# ============================================================
METHODS="GET POST PUT DELETE PATCH OPTIONS"

# ============================================================
# Test Function
# ============================================================
test_endpoint() {
    local endpoint="$1"
    local method="$2"
    local url="https://$TARGET$endpoint"
    
    # Build curl command
    local curl_opts=(-s -o /tmp/response_body.txt -w "%{http_code}|%{content_type}|%{size_download}")
    curl_opts+=(-X "$method")
    curl_opts+=(--connect-timeout 5)
    curl_opts+=(-H "Content-Type: application/json")
    curl_opts+=(-H "Accept: application/json")
    
    # Add auth token if provided
    if [ -n "$AUTH_TOKEN" ]; then
        curl_opts+=(-H "Authorization: Bearer $AUTH_TOKEN")
    fi
    
    # Add empty body for methods that expect it
    if [[ "$method" =~ ^(POST|PUT|PATCH)$ ]]; then
        curl_opts+=(-d '{}')
    fi
    
    # Execute request
    local result
    result=$(curl "${curl_opts[@]}" "$url" 2>/dev/null)
    
    local http_code=$(echo "$result" | cut -d'|' -f1)
    local content_type=$(echo "$result" | cut -d'|' -f2)
    local size=$(echo "$result" | cut -d'|' -f3)
    
    # Analyze response
    local notes=""
    local response_body=$(cat /tmp/response_body.txt 2>/dev/null)
    
    case "$http_code" in
        200)
            # Check for sensitive data in response
            if echo "$response_body" | grep -qiE "api_key|token|secret|password|credit"; then
                notes="⚠️ Potential sensitive data"
            elif echo "$response_body" | grep -qiE "\"count\":|\"results\":\[|\"users\":"; then
                notes="📊 Returns list data"
            elif echo "$response_body" | grep -qiE "\"email\"|\"user\""; then
                notes="👤 Contains user data"
            else
                notes="✓ OK"
            fi
            ;;
        201) notes="✓ Created" ;;
        204) notes="✓ No Content" ;;
        400) 
            if echo "$response_body" | grep -qiE "required|missing|invalid"; then
                param=$(echo "$response_body" | grep -oE '"[a-z_]+"\s*:.*required' | head -1 | cut -d'"' -f2)
                notes="Requires: ${param:-params}"
            else
                notes="Bad request"
            fi
            ;;
        401) notes="Auth required" ;;
        402) notes="Payment required" ;;
        403) notes="Forbidden" ;;
        404) notes="Not found" ;;
        405) notes="Method not allowed" ;;
        429) notes="Rate limited" ;;
        500) notes="Server error" ;;
        502|503|504) notes="Service unavailable" ;;
        000) notes="Connection failed" ;;
        *) notes="HTTP $http_code" ;;
    esac
    
    echo "$method|$endpoint|$http_code|$notes"
}

# ============================================================
# Run Tests
# ============================================================
echo "Testing $(wc -l < endpoints-to-test.txt) endpoints with $METHODS..."
echo ""

# Initialize results file
echo "# Endpoint Test Results" > test-results.md
echo "" >> test-results.md
echo "**Target:** $TARGET" >> test-results.md
echo "**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> test-results.md
echo "**Auth:** $([ -n "$AUTH_TOKEN" ] && echo "Bearer token provided" || echo "None")" >> test-results.md
echo "" >> test-results.md

# Group endpoints by category
declare -A CATEGORIES
CATEGORIES["User Dashboard"]="/user_dashboard"
CATEGORIES["Authentication"]="/auth"
CATEGORIES["Billing/Payments"]="/billing|/payment|/tenant"
CATEGORIES["Admin"]="/admin|/internal"
CATEGORIES["API Core"]="/api|/v[0-9]|/graphql"
CATEGORIES["Data/Search"]="/search|/screener|/person|/company|/job|/web"
CATEGORIES["Integrations"]="/slack|/webhook|/oauth"
CATEGORIES["Config/Status"]="/health|/status|/metrics|/debug|/.well-known"

# Test each category
for category in "User Dashboard" "Authentication" "Billing/Payments" "Admin" "API Core" "Data/Search" "Integrations" "Config/Status" "Other"; do
    pattern="${CATEGORIES[$category]:-^/}"
    
    # Get endpoints for this category
    if [ "$category" = "Other" ]; then
        # Endpoints not matching any category
        endpoints=$(cat endpoints-to-test.txt | grep -vE "/user_dashboard|/auth|/billing|/payment|/tenant|/admin|/internal|/api|/v[0-9]|/graphql|/search|/screener|/person|/company|/job|/web|/slack|/webhook|/oauth|/health|/status|/metrics|/debug|/.well-known")
    else
        endpoints=$(cat endpoints-to-test.txt | grep -E "$pattern")
    fi
    
    if [ -z "$endpoints" ]; then
        continue
    fi
    
    echo "## $category" >> test-results.md
    echo "" >> test-results.md
    echo "| Method | Endpoint | Status | Notes |" >> test-results.md
    echo "|--------|----------|--------|-------|" >> test-results.md
    
    for endpoint in $endpoints; do
        for method in $METHODS; do
            result=$(test_endpoint "$endpoint" "$method")
            m=$(echo "$result" | cut -d'|' -f1)
            e=$(echo "$result" | cut -d'|' -f2)
            code=$(echo "$result" | cut -d'|' -f3)
            notes=$(echo "$result" | cut -d'|' -f4)
            
            # Skip if connection failed
            [ "$code" = "000" ] && continue
            
            # Format status with color indicators
            case "$code" in
                200|201|204) status="✅ $code" ;;
                400|401|402|403|405) status="🔒 $code" ;;
                404) status="⬜ $code" ;;
                *) status="⚠️ $code" ;;
            esac
            
            echo "| $m | $e | $status | $notes |" >> test-results.md
        done
    done
    
    echo "" >> test-results.md
done

# ============================================================
# Findings Summary
# ============================================================
echo "## Findings Summary" >> test-results.md
echo "" >> test-results.md

# Count results
total_200=$(grep -c "✅ 200\|✅ 201" test-results.md 2>/dev/null || echo "0")
total_auth=$(grep -c "🔒 401\|🔒 403" test-results.md 2>/dev/null || echo "0")
total_interesting=$(grep -c "⚠️\|Potential sensitive\|Returns list\|Contains user" test-results.md 2>/dev/null || echo "0")

echo "- **Accessible endpoints (200/201):** $total_200" >> test-results.md
echo "- **Auth-required endpoints (401/403):** $total_auth" >> test-results.md
echo "- **Interesting findings:** $total_interesting" >> test-results.md
echo "" >> test-results.md

# Highlight interesting findings
echo "### Interesting Findings" >> test-results.md
echo "" >> test-results.md
grep -E "Potential sensitive|Returns list|Contains user|✅ 200.*POST|✅ 200.*PUT|✅ 200.*DELETE" test-results.md >> interesting-findings.md 2>/dev/null || echo "None" >> test-results.md

# ============================================================
# Output
# ============================================================
cat test-results.md

echo ""
echo "Full results saved to: $OUTPUT_DIR/test-results.md"
