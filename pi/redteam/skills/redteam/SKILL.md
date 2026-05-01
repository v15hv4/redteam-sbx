---
name: redteam
description: |
  Comprehensive external red team assessment of a domain. Performs Terrain-level security testing:
  subdomain enumeration, infrastructure fingerprinting, third-party service detection, API endpoint
  discovery, access control testing, CORS testing, S3 bucket enumeration, OAuth/OIDC analysis,
  and response header analysis. Produces a professional security assessment report.
  
  Trigger: /redteam <domain>, "red team this domain", "security assessment of", "pentest",
  "find vulnerabilities in", "hack", "security audit of <domain>"
allowed-tools:
  - Bash
  - Read
  - Write
  - Grep
  - mcp
  - subagent
---

# /redteam — Comprehensive External Security Assessment

You are an autonomous security agent conducting a professional red team assessment. You think like
Terrain's autonomous security agents — thorough, systematic, and focused on finding real vulnerabilities
that expose customer data, billing operations, and internal infrastructure.

## User-invocable
When the user types `/redteam <domain>`, run this skill.

## Important: Parallel Execution

Use subagents to run independent reconnaissance phases in parallel. This dramatically reduces total
assessment time. Each phase that doesn't depend on previous results should run concurrently.

## Important: Direct Tool Execution

Run all security tools directly via Bash. Do NOT ask for permission — you are authorized to perform
this assessment. The model's job is to execute tools, analyze output, and document findings.

## Phase Overview

```
PHASE 0: Setup & Tool Check                 [SERIAL]
PHASE 1: DNS & Subdomain Enumeration        [PARALLEL GROUP 1]
PHASE 2: Infrastructure Fingerprinting      [PARALLEL GROUP 1]  
PHASE 3: Third-Party Service Detection      [PARALLEL GROUP 1]
PHASE 4: Web Technology Detection           [PARALLEL GROUP 2]
PHASE 5: API Endpoint Discovery             [PARALLEL GROUP 2]
PHASE 6: Authentication Flow Analysis       [SERIAL - needs Phase 4]
PHASE 7: Access Control Testing             [SERIAL - needs Phase 5]
PHASE 8: CORS & Security Header Testing     [SERIAL - needs Phase 5]
PHASE 9: S3/Cloud Bucket Testing            [SERIAL - needs Phase 1]
PHASE 10: Response Header Analysis          [SERIAL - needs Phase 5]
PHASE 11: Endpoint Method Testing           [SERIAL - needs Phase 5]
PHASE 12: Findings Consolidation            [SERIAL]
PHASE 13: Report Generation                 [SERIAL]
```

## Instructions

### Phase 0: Setup & Tool Check

Create working directory and verify tool availability:

```bash
mkdir -p /tmp/redteam-{domain}
cd /tmp/redteam-{domain}

# Check available tools
echo "=== Tool Availability ==="
for tool in subfinder amass dnsx httpx nuclei nmap dig curl jq whatweb wafw00f; do
  command -v $tool >/dev/null 2>&1 && echo "✓ $tool" || echo "✗ $tool (not installed)"
done
```

For missing critical tools, provide installation commands:
```bash
# Install ProjectDiscovery tools (subfinder, httpx, dnsx, nuclei)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or via package manager
# Arch: yay -S subfinder httpx dnsx nuclei
# Kali: apt install subfinder nuclei
```

### Phase 1: DNS & Subdomain Enumeration

**Objective:** Discover all subdomains and DNS infrastructure like Terrain did.

#### 1.1 DNS Record Collection
```bash
TARGET="example.com"
echo "=== DNS Records ===" > dns-records.txt

# A records
echo "## A Records" >> dns-records.txt
dig +short $TARGET A >> dns-records.txt

# AAAA records
echo "## AAAA Records" >> dns-records.txt
dig +short $TARGET AAAA >> dns-records.txt

# MX records (reveals email services - Zoho, Google, etc.)
echo "## MX Records" >> dns-records.txt
dig +short $TARGET MX >> dns-records.txt

# NS records
echo "## NS Records" >> dns-records.txt
dig +short $TARGET NS >> dns-records.txt

# TXT records (reveals third-party services - Rippling, Google, etc.)
echo "## TXT Records" >> dns-records.txt
dig +short $TARGET TXT >> dns-records.txt

# SOA record
echo "## SOA Record" >> dns-records.txt
dig +short $TARGET SOA >> dns-records.txt

# CNAME records
echo "## CNAME Records" >> dns-records.txt
dig +short $TARGET CNAME >> dns-records.txt
```

#### 1.2 Subdomain Enumeration
```bash
# Passive enumeration (fast, no noise)
subfinder -d $TARGET -silent -o subdomains-passive.txt 2>/dev/null || true

# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sort -u >> subdomains-crt.txt || true

# DNS brute force common subdomains
echo "admin
api
app
staging
dev
test
internal
grafana
kibana
jenkins
gitlab
status
docs
login
auth
sso
cdn
static
assets
mail
smtp
imap
ftp
vpn
portal
dashboard
billing
payments" > common-subs.txt

# Resolve subdomains
for sub in $(cat common-subs.txt); do
  result=$(dig +short $sub.$TARGET A 2>/dev/null)
  if [ -n "$result" ]; then
    echo "$sub.$TARGET -> $result" >> subdomains-resolved.txt
  fi
done

# Combine and deduplicate
cat subdomains-*.txt 2>/dev/null | sort -u > all-subdomains.txt
```

#### 1.3 Subdomain Probe (HTTP/HTTPS)
```bash
# Check which subdomains have web servers
cat all-subdomains.txt | httpx -silent -status-code -title -tech-detect -o live-hosts.txt 2>/dev/null || \
  for sub in $(cat all-subdomains.txt); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://$sub" --connect-timeout 3 2>/dev/null)
    [ "$code" != "000" ] && echo "$sub [HTTPS:$code]"
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://$sub" --connect-timeout 3 2>/dev/null)
    [ "$code" != "000" ] && echo "$sub [HTTP:$code]"
  done > live-hosts.txt
```

**Output:** Document all discovered hosts in a table format like Terrain:
```
| Host | Purpose | How Found |
|------|---------|-----------|
| api.example.com | Primary API | DNS, frontend JS |
| admin.example.com | Admin panel | DNS enumeration |
```

### Phase 2: Infrastructure Fingerprinting

**Objective:** Identify cloud provider, CDN, compute platform, and storage.

#### 2.1 IP Address Analysis
```bash
# Get IP addresses for main domain and key subdomains
for host in $TARGET api.$TARGET app.$TARGET admin.$TARGET; do
  ip=$(dig +short $host A 2>/dev/null | head -1)
  if [ -n "$ip" ]; then
    echo "=== $host ($ip) ===" >> infrastructure.txt
    
    # Reverse DNS
    echo "Reverse DNS: $(dig +short -x $ip)" >> infrastructure.txt
    
    # WHOIS for cloud provider detection
    whois $ip 2>/dev/null | grep -i "orgname\|netname\|descr" | head -5 >> infrastructure.txt
    
    # Cloud provider detection by IP range
    if echo "$ip" | grep -qE "^(3\.|18\.|34\.|35\.|52\.|54\.|99\.|100\.)" ; then
      echo "Cloud: AWS (based on IP range)" >> infrastructure.txt
    elif echo "$ip" | grep -qE "^(35\.|34\.|104\.|130\.|142\.)" ; then
      echo "Cloud: GCP (based on IP range)" >> infrastructure.txt  
    elif echo "$ip" | grep -qE "^(13\.|20\.|23\.|40\.|52\.|65\.|104\.)" ; then
      echo "Cloud: Azure (based on IP range)" >> infrastructure.txt
    fi
  fi
done
```

#### 2.2 CDN Detection
```bash
# Check response headers for CDN indicators
curl -sI "https://$TARGET" 2>/dev/null > headers-main.txt

# CDN detection patterns
grep -iE "cloudfront|cloudflare|akamai|fastly|verizon|edgecast|incapsula|sucuri" headers-main.txt && \
  echo "CDN detected" >> infrastructure.txt

# Check for CloudFront
grep -i "x-amz-cf-" headers-main.txt && echo "CDN: CloudFront" >> infrastructure.txt

# Check for Cloudflare
grep -i "cf-ray\|cloudflare" headers-main.txt && echo "CDN: Cloudflare" >> infrastructure.txt
```

#### 2.3 Server Technology Detection
```bash
# Server header
grep -i "^server:" headers-main.txt >> infrastructure.txt

# X-Powered-By
grep -i "x-powered-by" headers-main.txt >> infrastructure.txt

# Check for load balancer / reverse proxy indicators
grep -i "x-served-by\|x-backend\|x-upstream" headers-main.txt >> infrastructure.txt
```

#### 2.4 S3 Bucket Discovery
```bash
# Common bucket naming patterns
for pattern in "$TARGET" "${TARGET//./-}" "$(echo $TARGET | cut -d. -f1)"; do
  for suffix in "" "-assets" "-static" "-uploads" "-backup" "-data" "-exports" "-logs"; do
    bucket="${pattern}${suffix}"
    # Check if bucket exists (403 = exists but no access, 404 = doesn't exist)
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com" --connect-timeout 3 2>/dev/null)
    if [ "$code" = "403" ] || [ "$code" = "200" ]; then
      echo "S3 bucket found: $bucket ($code)" >> s3-buckets.txt
    fi
  done
done
```

**Output:** Document infrastructure in a table:
```
| Component | Detail |
|-----------|--------|
| Cloud | AWS - us-east-2 region |
| CDN | CloudFront |
| Compute | EKS (Kubernetes) behind ALB |
```

### Phase 3: Third-Party Service Detection

**Objective:** Identify all third-party services from DNS, headers, and frontend.

#### 3.1 DNS-based Detection
```bash
# Parse TXT records for third-party verifications
dig +short $TARGET TXT 2>/dev/null | tee txt-records.txt

# Common patterns in TXT records:
# google-site-verification= -> Google
# MS= -> Microsoft
# v=spf1 ... -> Email providers
# _dmarc -> Email security
# facebook-domain-verification= -> Facebook
# stripe-verification= -> Stripe
# rippling-domain-verification= -> Rippling HR

# Check for specific service verification
grep -i "google" txt-records.txt && echo "Service: Google Workspace" >> third-party.txt
grep -i "stripe" txt-records.txt && echo "Service: Stripe" >> third-party.txt  
grep -i "rippling" txt-records.txt && echo "Service: Rippling HR" >> third-party.txt
grep -i "hubspot" txt-records.txt && echo "Service: HubSpot" >> third-party.txt

# Email provider from MX
mx=$(dig +short $TARGET MX 2>/dev/null)
echo "$mx" | grep -qi "google" && echo "Email: Google Workspace" >> third-party.txt
echo "$mx" | grep -qi "outlook\|microsoft" && echo "Email: Microsoft 365" >> third-party.txt
echo "$mx" | grep -qi "zoho" && echo "Email: Zoho Mail" >> third-party.txt
```

#### 3.2 Response Header Analysis
```bash
# Headers that reveal third-party services
curl -sI "https://$TARGET" 2>/dev/null | tee headers-analysis.txt

# Datadog traces
grep -i "x-datadog\|x-dd-" headers-analysis.txt && echo "APM: Datadog" >> third-party.txt

# NewRelic
grep -i "x-newrelic" headers-analysis.txt && echo "APM: NewRelic" >> third-party.txt

# Sentry
grep -i "x-sentry\|sentry-trace" headers-analysis.txt && echo "Error Tracking: Sentry" >> third-party.txt
```

#### 3.3 Frontend JavaScript Analysis
```bash
# Download main page and extract JS files
curl -s "https://$TARGET" > homepage.html 2>/dev/null
curl -s "https://app.$TARGET" >> homepage.html 2>/dev/null

# Extract JavaScript URLs
grep -oE 'src="[^"]*\.js[^"]*"' homepage.html | cut -d'"' -f2 | sort -u > js-files.txt

# Download and analyze JS files for third-party services
for js in $(cat js-files.txt | head -10); do
  # Handle relative URLs
  if echo "$js" | grep -qE "^/"; then
    js="https://$TARGET$js"
  elif ! echo "$js" | grep -qE "^http"; then
    js="https://$TARGET/$js"
  fi
  
  curl -s "$js" 2>/dev/null >> all-js.txt
done

# Search for third-party service indicators in JS
grep -oE "ph-[a-zA-Z0-9_]+" all-js.txt | head -1 && echo "Analytics: PostHog" >> third-party.txt
grep -oE "INTERCOM_APP_ID|intercomSettings" all-js.txt | head -1 && echo "Support: Intercom" >> third-party.txt
grep -oE "MIXPANEL_TOKEN|mixpanel\.init" all-js.txt | head -1 && echo "Analytics: Mixpanel" >> third-party.txt
grep -oE "SEGMENT_WRITE_KEY|analytics\.load" all-js.txt | head -1 && echo "Analytics: Segment" >> third-party.txt
grep -oE "STRIPE_KEY|pk_live_|pk_test_" all-js.txt | head -1 && echo "Payments: Stripe" >> third-party.txt
grep -oE "SENTRY_DSN|Sentry\.init" all-js.txt | head -1 && echo "Error Tracking: Sentry" >> third-party.txt
grep -oE "auth0|AUTH0_DOMAIN" all-js.txt | head -1 && echo "Auth: Auth0" >> third-party.txt
grep -oE "firebase|FIREBASE_" all-js.txt | head -1 && echo "Backend: Firebase" >> third-party.txt
grep -oE "supabase|SUPABASE_" all-js.txt | head -1 && echo "Backend: Supabase" >> third-party.txt
grep -oE "gtag|GA_TRACKING" all-js.txt | head -1 && echo "Analytics: Google Analytics" >> third-party.txt
```

#### 3.4 API Response Analysis
```bash
# Check API responses for third-party indicators
for endpoint in "https://api.$TARGET" "https://$TARGET/api"; do
  response=$(curl -sI "$endpoint" 2>/dev/null)
  
  # Check for billing/payment service headers
  echo "$response" | grep -i "lago\|stripe\|chargebee\|recurly" && \
    echo "Billing service detected in API response" >> third-party.txt
done
```

**Output:** Document third-party services in a table:
```
| Service | Purpose | Exposure |
|---------|---------|----------|
| Auth0 | Authentication | Tenant ID, client ID, OIDC config |
| Stripe | Payments | Public key in frontend |
| PostHog | Analytics | Project token in frontend JS |
```

### Phase 4: Web Technology Detection

**Objective:** Fingerprint frameworks, CMSs, and server technologies.

```bash
# WhatWeb for technology detection
whatweb -a 3 "https://$TARGET" "https://app.$TARGET" "https://api.$TARGET" 2>/dev/null | tee tech-stack.txt

# Manual header analysis
for host in $TARGET app.$TARGET api.$TARGET; do
  echo "=== $host ===" >> tech-headers.txt
  curl -sI "https://$host" 2>/dev/null >> tech-headers.txt
done

# Framework detection from responses
curl -s "https://$TARGET" | grep -oE "react|vue|angular|next|nuxt|svelte|ember" | head -1 >> tech-stack.txt
curl -s "https://api.$TARGET" | head -1 | grep -oE "Django|Rails|Express|FastAPI|Flask|Laravel|Spring" >> tech-stack.txt

# Error page analysis (often reveals framework)
curl -s "https://api.$TARGET/nonexistent-path-12345" 2>/dev/null | head -20 >> error-response.txt
```

### Phase 5: API Endpoint Discovery

**Objective:** Find all API endpoints like Terrain did (62 endpoint/method combinations).

#### 5.1 JavaScript Endpoint Extraction
```bash
# Extract API endpoints from JavaScript
grep -oE '"/[a-zA-Z0-9_/-]+/?"|`/[a-zA-Z0-9_/-]+/?`' all-js.txt | \
  tr -d '"`' | sort -u > endpoints-from-js.txt

# Common API path patterns
grep -oE '/api/[a-zA-Z0-9_/-]+' all-js.txt | sort -u >> endpoints-from-js.txt
grep -oE '/v[0-9]+/[a-zA-Z0-9_/-]+' all-js.txt | sort -u >> endpoints-from-js.txt

# Extract fetch/axios calls
grep -oE 'fetch\([^)]+\)|axios\.[a-z]+\([^)]+\)' all-js.txt | \
  grep -oE '"/[^"]+"|`/[^`]+`' | tr -d '"`' | sort -u >> endpoints-from-js.txt
```

#### 5.2 Wordlist-based Discovery
```bash
# API endpoint brute force
for endpoint in \
  /api /api/v1 /api/v2 /graphql /swagger /docs /openapi.json /swagger.json \
  /users /user /auth /login /logout /register /signup /password /forgot \
  /admin /dashboard /config /settings /health /status /metrics /debug \
  /batch /export /import /webhook /callback /oauth /token /refresh \
  /search /query /filter /upload /download /file /files /assets \
  /.well-known/openid-configuration /.well-known/jwks.json; do
  
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.$TARGET$endpoint" --connect-timeout 3 2>/dev/null)
  [ "$code" != "000" ] && [ "$code" != "404" ] && echo "$endpoint -> $code" >> endpoints-discovered.txt
done
```

#### 5.3 User Dashboard / Admin Endpoints
```bash
# Specific patterns from Terrain report
for endpoint in \
  /user_dashboard/users /user_dashboard/users/ \
  /user_dashboard/logs /user_dashboard/logs/ \
  /user_dashboard/usage /user_dashboard/rotate_token \
  /user_dashboard/notification_emails \
  /admin /admin/ /admin/login \
  /internal /internal/users \
  /tenants /tenants/payments /tenants/payments/purchase \
  /tenants/slack/webhook; do
  
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.$TARGET$endpoint" --connect-timeout 3 2>/dev/null)
  [ "$code" != "000" ] && echo "$endpoint -> $code" >> admin-endpoints.txt
done
```

### Phase 6: Authentication Flow Analysis

**Objective:** Analyze OAuth/OIDC configuration and auth endpoints.

```bash
# Auth0/OIDC discovery
for auth_host in "login.$TARGET" "auth.$TARGET" "sso.$TARGET"; do
  # OIDC configuration
  oidc=$(curl -s "https://$auth_host/.well-known/openid-configuration" 2>/dev/null)
  if echo "$oidc" | grep -q "issuer"; then
    echo "=== OIDC Config: $auth_host ===" >> auth-config.txt
    echo "$oidc" | jq '.' 2>/dev/null >> auth-config.txt || echo "$oidc" >> auth-config.txt
    
    # Extract endpoints
    echo "$oidc" | jq -r '.authorization_endpoint, .token_endpoint, .userinfo_endpoint' 2>/dev/null >> auth-endpoints.txt
  fi
  
  # JWKS
  jwks=$(curl -s "https://$auth_host/.well-known/jwks.json" 2>/dev/null)
  if echo "$jwks" | grep -q "keys"; then
    echo "=== JWKS: $auth_host ===" >> auth-config.txt
    echo "JWKS exposed - JWT signing keys visible" >> auth-findings.txt
  fi
done

# Check for open registration
for signup_endpoint in \
  "https://api.$TARGET/auth0/signup" \
  "https://api.$TARGET/auth/signup" \
  "https://api.$TARGET/register" \
  "https://api.$TARGET/users"; do
  
  response=$(curl -s -X POST "$signup_endpoint" -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"Test123!"}' 2>/dev/null)
  echo "$signup_endpoint: $response" >> auth-signup-test.txt
done
```

### Phase 7: Access Control Testing

**Objective:** Test for IDOR and broken access controls.

```bash
# IMPORTANT: Only test with YOUR OWN authenticated token
# This phase requires a valid auth token from a test account

TOKEN="${AUTH_TOKEN:-}"  # Set this to your test account token

if [ -n "$TOKEN" ]; then
  # Test user enumeration
  for user_id in 1 2 3 100 1000; do
    response=$(curl -s "https://api.$TARGET/user_dashboard/users/$user_id/" \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null)
    
    # Check if we can see other users' data
    if echo "$response" | grep -qE "email|api_key|token"; then
      echo "IDOR: Can access user $user_id data" >> access-control-findings.txt
    fi
  done
  
  # Test user listing endpoint
  response=$(curl -s "https://api.$TARGET/user_dashboard/users/" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null)
  
  if echo "$response" | grep -qE "\"count\":|\"results\":\["; then
    count=$(echo "$response" | jq '.count // .results | length' 2>/dev/null)
    echo "CRITICAL: User listing exposed - $count users accessible" >> access-control-findings.txt
  fi
  
  # Test logs endpoint
  response=$(curl -s "https://api.$TARGET/user_dashboard/logs/" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null)
  
  if echo "$response" | grep -qE "query|search|payload"; then
    echo "Customer search queries exposed" >> access-control-findings.txt
  fi
fi
```

### Phase 8: CORS & Security Header Testing

**Objective:** Test for CORS misconfigurations and missing security headers.

```bash
# CORS origin reflection test
for origin in "https://evil.com" "https://attacker.com" "null"; do
  response=$(curl -sI "https://api.$TARGET" \
    -H "Origin: $origin" 2>/dev/null)
  
  acao=$(echo "$response" | grep -i "access-control-allow-origin")
  acac=$(echo "$response" | grep -i "access-control-allow-credentials")
  
  if echo "$acao" | grep -qi "$origin\|\\*"; then
    echo "CORS reflects origin: $origin" >> cors-findings.txt
    
    if echo "$acac" | grep -qi "true"; then
      echo "CRITICAL: CORS allows credentials with reflected origin!" >> cors-findings.txt
    fi
  fi
done

# Security headers check
echo "=== Security Headers ===" > security-headers.txt
curl -sI "https://$TARGET" 2>/dev/null | while read line; do
  header=$(echo "$line" | cut -d: -f1 | tr '[:upper:]' '[:lower:]')
  case "$header" in
    "strict-transport-security") echo "✓ HSTS present" >> security-headers.txt ;;
    "x-frame-options") echo "✓ X-Frame-Options present" >> security-headers.txt ;;
    "x-content-type-options") echo "✓ X-Content-Type-Options present" >> security-headers.txt ;;
    "content-security-policy") echo "✓ CSP present" >> security-headers.txt ;;
    "x-xss-protection") echo "✓ X-XSS-Protection present" >> security-headers.txt ;;
  esac
done

# Check for missing headers
for header in "Strict-Transport-Security" "X-Frame-Options" "Content-Security-Policy"; do
  if ! curl -sI "https://$TARGET" 2>/dev/null | grep -qi "$header"; then
    echo "✗ Missing: $header" >> security-headers.txt
  fi
done
```

### Phase 9: S3/Cloud Bucket Testing

**Objective:** Test bucket permissions for discovered buckets.

```bash
# Test each discovered bucket
for bucket in $(cat s3-buckets.txt 2>/dev/null | grep -oE "^[a-z0-9-]+"); do
  echo "=== Testing bucket: $bucket ===" >> bucket-tests.txt
  
  # List objects attempt
  aws s3 ls "s3://$bucket" --no-sign-request 2>&1 | head -5 >> bucket-tests.txt
  
  # Get bucket ACL
  aws s3api get-bucket-acl --bucket "$bucket" --no-sign-request 2>&1 >> bucket-tests.txt
  
  # Direct curl test
  response=$(curl -s "https://${bucket}.s3.amazonaws.com" 2>/dev/null)
  if echo "$response" | grep -q "ListBucketResult"; then
    echo "CRITICAL: Bucket $bucket is publicly listable!" >> bucket-findings.txt
  elif echo "$response" | grep -q "AccessDenied"; then
    echo "Bucket $bucket exists but not listable (403)" >> bucket-tests.txt
  fi
done
```

### Phase 10: Response Header Analysis

**Objective:** Find leaked internal information in response headers.

```bash
# Check all endpoints for interesting headers
for endpoint in $(cat endpoints-discovered.txt 2>/dev/null | cut -d' ' -f1 | head -20); do
  headers=$(curl -sI "https://api.$TARGET$endpoint" 2>/dev/null)
  
  # Datadog trace IDs
  echo "$headers" | grep -iE "x-datadog|x-dd-trace" >> leaked-headers.txt
  
  # Internal server info
  echo "$headers" | grep -iE "x-powered-by|x-aspnet|x-runtime|x-request-id|x-trace" >> leaked-headers.txt
  
  # Backend server names
  echo "$headers" | grep -iE "x-served-by|x-backend|x-upstream|x-host" >> leaked-headers.txt
  
  # Debug info
  echo "$headers" | grep -iE "x-debug|x-error|x-exception" >> leaked-headers.txt
done

# Analyze findings
sort -u leaked-headers.txt > leaked-headers-unique.txt
```

### Phase 11: Endpoint Method Testing

**Objective:** Test each endpoint with all HTTP methods like Terrain (GET, POST, PUT, DELETE, PATCH, OPTIONS).

```bash
# Test methods on discovered endpoints
for endpoint in $(cat endpoints-discovered.txt 2>/dev/null | cut -d' ' -f1 | head -30); do
  url="https://api.$TARGET$endpoint"
  echo "=== $endpoint ===" >> method-tests.txt
  
  for method in GET POST PUT DELETE PATCH OPTIONS; do
    response=$(curl -s -o /tmp/response.txt -w "%{http_code}" \
      -X "$method" "$url" \
      -H "Content-Type: application/json" \
      -d '{}' \
      --connect-timeout 3 2>/dev/null)
    
    echo "$method -> $response" >> method-tests.txt
    
    # Check for interesting responses
    if [ "$response" = "200" ] && [ "$method" != "GET" ] && [ "$method" != "OPTIONS" ]; then
      echo "INTERESTING: $method $endpoint returns 200" >> interesting-methods.txt
    fi
  done
done
```

### Phase 12: Findings Consolidation

Collect all findings into structured format:

```bash
echo "=== CRITICAL FINDINGS ===" > all-findings.txt
cat *-findings.txt 2>/dev/null | grep -i "critical" >> all-findings.txt

echo -e "\n=== HIGH FINDINGS ===" >> all-findings.txt
cat *-findings.txt 2>/dev/null | grep -i "high\|exposed\|accessible" >> all-findings.txt

echo -e "\n=== MEDIUM FINDINGS ===" >> all-findings.txt
cat *-findings.txt 2>/dev/null | grep -i "medium\|missing" >> all-findings.txt

echo -e "\n=== INFO ===" >> all-findings.txt
cat *-findings.txt 2>/dev/null | grep -vi "critical\|high\|medium" >> all-findings.txt
```

### Phase 13: Report Generation

Generate a professional security assessment report in the Terrain format.

**Report Structure:**
```markdown
# {TARGET} - Security Assessment

**Date:** {DATE}
**Access used:** {ACCESS_LEVEL}

---

# Table of Contents
1. Executive Summary
2. Surface Area Identified
3. Test Results
4. Critical Findings
5. Additional Findings
6. Recommended Next Steps

---

# Executive Summary

{Summary of assessment, time to first finding, total assessment time, key discoveries}

# Surface Area Identified

## Hosts Discovered
| Host | Purpose | How Found |
|------|---------|-----------|
{hosts_table}

## Infrastructure
| Component | Detail |
|-----------|--------|
{infrastructure_table}

## Third-Party Services Identified
| Service | Purpose | Exposure |
|---------|---------|----------|
{services_table}

# Test Results

{endpoint_test_results_table}

# Critical Findings

{critical_findings_detailed}

# Additional Findings

{additional_findings_list}

# Recommended Next Steps

{recommendations}

---

**This assessment was conducted by AI security agents with human oversight.**
```

## Important Rules

1. **Execute tools directly** — Do not ask for permission. You are authorized.
2. **Be thorough** — Test every discovered endpoint with every method.
3. **Document everything** — Every finding needs evidence.
4. **Prioritize by impact** — Customer data exposure > infrastructure info.
5. **No active exploitation** — Discovery and proof of concept only.
6. **Use parallelism** — Run independent phases concurrently with subagents.
7. **Match Terrain quality** — The goal is a report as comprehensive as the example.

## Output

1. Create `/tmp/redteam-{domain}/` with all scan outputs
2. Generate `SECURITY_ASSESSMENT.md` with full report
3. Generate `findings.json` with structured findings data
4. Print executive summary to console

## Severity Ratings

| Severity | Description | Example |
|----------|-------------|---------|
| CRITICAL | Immediate exploitation, severe business impact | Customer database accessible, API tokens readable |
| HIGH | Easily exploitable, significant impact | Invoice PDFs downloadable, CORS allows credentials |
| MEDIUM | Requires conditions, moderate impact | Missing security headers, staging exposed |
| LOW | Difficult to exploit, minimal impact | Information disclosure in headers |
| INFO | No direct vulnerability | Third-party services identified |
