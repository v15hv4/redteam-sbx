#!/bin/bash
# Third-Party Service Detection Script
# Comprehensive detection of SaaS services from DNS, headers, and frontend JS

TARGET="${1:-example.com}"
OUTPUT_DIR="${2:-/tmp/redteam-$TARGET}"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "=== Third-Party Service Detection for $TARGET ==="
echo ""

# ============================================================
# DNS-Based Detection
# ============================================================
echo "## DNS-Based Detection" > third-party-services.md
echo "" >> third-party-services.md

# TXT Records (service verifications)
echo "### TXT Records" >> third-party-services.md
dig +short "$TARGET" TXT > txt-records.txt 2>/dev/null

# Service patterns in TXT records
declare -A TXT_PATTERNS=(
    ["google-site-verification"]="Google Workspace"
    ["MS="]="Microsoft 365"
    ["stripe-verification"]="Stripe (Payments)"
    ["rippling-domain-verification"]="Rippling (HR/Payroll)"
    ["hubspot-domain-verification"]="HubSpot (CRM)"
    ["facebook-domain-verification"]="Facebook/Meta"
    ["atlassian-domain-verification"]="Atlassian"
    ["adobe-idp-site-verification"]="Adobe"
    ["docusign"]="DocuSign"
    ["zendesk-domain-verification"]="Zendesk (Support)"
    ["spf1"]="Email (SPF configured)"
    ["DKIM"]="Email (DKIM configured)"
    ["brevo-code"]="Brevo (Email Marketing)"
    ["mailchimp"]="Mailchimp"
    ["sendgrid"]="SendGrid"
    ["postmark"]="Postmark"
    ["apple-domain-verification"]="Apple"
    ["have-i-been-pwned-verification"]="HIBP"
    ["loaderio"]="Loader.io (Load Testing)"
)

echo "| Pattern Found | Service |" >> third-party-services.md
echo "|---------------|---------|" >> third-party-services.md

for pattern in "${!TXT_PATTERNS[@]}"; do
    if grep -qi "$pattern" txt-records.txt 2>/dev/null; then
        echo "| $pattern | ${TXT_PATTERNS[$pattern]} |" >> third-party-services.md
    fi
done
echo "" >> third-party-services.md

# MX Records (email provider)
echo "### MX Records (Email Provider)" >> third-party-services.md
dig +short "$TARGET" MX > mx-records.txt 2>/dev/null

declare -A MX_PROVIDERS=(
    ["google"]="Google Workspace"
    ["googlemail"]="Google Workspace"
    ["outlook"]="Microsoft 365"
    ["microsoft"]="Microsoft 365"
    ["zoho"]="Zoho Mail"
    ["protonmail"]="ProtonMail"
    ["postmarkapp"]="Postmark"
    ["sendgrid"]="SendGrid"
    ["mailgun"]="Mailgun"
    ["amazonses"]="AWS SES"
    ["mimecast"]="Mimecast"
    ["barracuda"]="Barracuda"
)

for provider in "${!MX_PROVIDERS[@]}"; do
    if grep -qi "$provider" mx-records.txt 2>/dev/null; then
        echo "- Email Provider: ${MX_PROVIDERS[$provider]}" >> third-party-services.md
    fi
done
echo "" >> third-party-services.md

# ============================================================
# Response Header Analysis
# ============================================================
echo "### Response Headers" >> third-party-services.md
echo "" >> third-party-services.md

# Get headers from main domain and subdomains
for host in "$TARGET" "api.$TARGET" "app.$TARGET" "www.$TARGET"; do
    headers=$(curl -sI "https://$host" --connect-timeout 5 2>/dev/null)
    if [ -n "$headers" ]; then
        echo "$headers" >> all-headers.txt
    fi
done

# Header patterns
declare -A HEADER_PATTERNS=(
    ["x-datadog"]="Datadog (APM)"
    ["x-dd-trace"]="Datadog (Tracing)"
    ["x-newrelic"]="New Relic (APM)"
    ["x-sentry"]="Sentry (Error Tracking)"
    ["sentry-trace"]="Sentry (Tracing)"
    ["x-amz-cf"]="AWS CloudFront (CDN)"
    ["cf-ray"]="Cloudflare (CDN)"
    ["x-akamai"]="Akamai (CDN)"
    ["x-fastly"]="Fastly (CDN)"
    ["x-vercel"]="Vercel (Hosting)"
    ["x-netlify"]="Netlify (Hosting)"
    ["x-render"]="Render (Hosting)"
    ["x-heroku"]="Heroku (PaaS)"
    ["x-railway"]="Railway (PaaS)"
    ["x-fly"]="Fly.io (PaaS)"
    ["x-kong"]="Kong (API Gateway)"
    ["x-cache.*cloudflare"]="Cloudflare Cache"
    ["x-lago"]="Lago (Billing)"
    ["via.*varnish"]="Varnish (Cache)"
    ["x-envoy"]="Envoy Proxy"
)

echo "| Header Pattern | Service |" >> third-party-services.md
echo "|----------------|---------|" >> third-party-services.md

for pattern in "${!HEADER_PATTERNS[@]}"; do
    if grep -qiE "$pattern" all-headers.txt 2>/dev/null; then
        echo "| $pattern | ${HEADER_PATTERNS[$pattern]} |" >> third-party-services.md
    fi
done
echo "" >> third-party-services.md

# ============================================================
# Frontend JavaScript Analysis
# ============================================================
echo "### Frontend JavaScript Analysis" >> third-party-services.md
echo "" >> third-party-services.md

# Download frontend pages
for host in "$TARGET" "app.$TARGET" "www.$TARGET"; do
    curl -s "https://$host" --connect-timeout 5 2>/dev/null >> homepage.html
done

# Extract and download JS files
grep -oE 'src="[^"]*\.js[^"]*"|src='"'"'[^'"'"']*\.js[^'"'"']*'"'" homepage.html 2>/dev/null | \
    sed "s/src=[\"']//;s/[\"']//" | \
    sort -u > js-urls.txt

# Resolve relative URLs and download
while read -r js_url; do
    if [[ "$js_url" == /* ]]; then
        full_url="https://$TARGET$js_url"
    elif [[ "$js_url" != http* ]]; then
        full_url="https://$TARGET/$js_url"
    else
        full_url="$js_url"
    fi
    curl -s "$full_url" --connect-timeout 5 2>/dev/null >> all-js-content.txt
done < js-urls.txt

# Add inline scripts from HTML
grep -oE '<script[^>]*>.*?</script>' homepage.html 2>/dev/null >> all-js-content.txt

# Service patterns in JavaScript
declare -A JS_PATTERNS=(
    # Analytics
    ["posthog\\.init\\|ph-[a-zA-Z0-9_]+\\|POSTHOG"]="PostHog (Analytics)"
    ["mixpanel\\.init\\|MIXPANEL"]="Mixpanel (Analytics)"
    ["amplitude\\.init\\|AMPLITUDE"]="Amplitude (Analytics)"
    ["gtag\\|GA_TRACKING\\|google-analytics"]="Google Analytics"
    ["heap\\.load\\|HEAP_ID"]="Heap (Analytics)"
    ["analytics\\.load\\|SEGMENT"]="Segment (Analytics)"
    ["plausible"]="Plausible (Analytics)"
    ["fathom"]="Fathom (Analytics)"
    
    # Support
    ["intercom\\|INTERCOM_APP"]="Intercom (Support)"
    ["crisp\\.chat\\|CRISP_WEBSITE"]="Crisp (Support)"
    ["drift\\.com\\|DRIFT_APP"]="Drift (Support)"
    ["zendesk\\|ZENDESK"]="Zendesk (Support)"
    ["freshdesk\\|FRESHDESK"]="Freshdesk (Support)"
    ["helpscout"]="Help Scout (Support)"
    
    # Auth
    ["auth0\\|AUTH0_DOMAIN\\|AUTH0_CLIENT"]="Auth0 (Authentication)"
    ["clerk\\.com\\|CLERK_"]="Clerk (Authentication)"
    ["supabase.*auth\\|SUPABASE_"]="Supabase Auth"
    ["firebase.*auth\\|FIREBASE_"]="Firebase Auth"
    ["okta\\.com\\|OKTA_"]="Okta (SSO)"
    ["cognito\\|COGNITO_"]="AWS Cognito"
    
    # Payments
    ["stripe\\.com\\|pk_live_\\|pk_test_\\|STRIPE_"]="Stripe (Payments)"
    ["paypal"]="PayPal"
    ["paddle"]="Paddle (Payments)"
    ["chargebee"]="Chargebee (Billing)"
    ["recurly"]="Recurly (Billing)"
    
    # Backend/Database
    ["supabase\\.co\\|SUPABASE_URL"]="Supabase (BaaS)"
    ["firebase\\|FIREBASE_"]="Firebase (BaaS)"
    ["mongodb\\.com\\|MONGODB_"]="MongoDB Atlas"
    ["planetscale"]="PlanetScale (MySQL)"
    
    # Error Tracking
    ["sentry\\.io\\|SENTRY_DSN\\|Sentry\\.init"]="Sentry (Errors)"
    ["bugsnag"]="Bugsnag (Errors)"
    ["rollbar"]="Rollbar (Errors)"
    ["logrocket"]="LogRocket (Session Replay)"
    ["fullstory"]="FullStory (Session Replay)"
    ["hotjar"]="Hotjar (Heatmaps)"
    
    # Feature Flags
    ["launchdarkly"]="LaunchDarkly (Feature Flags)"
    ["split\\.io"]="Split.io (Feature Flags)"
    ["optimizely"]="Optimizely (A/B Testing)"
    
    # CMS/Forms
    ["contentful"]="Contentful (CMS)"
    ["sanity\\.io"]="Sanity (CMS)"
    ["typeform"]="Typeform (Forms)"
    
    # CDN/Assets
    ["cloudinary"]="Cloudinary (Media)"
    ["imgix"]="Imgix (Images)"
    ["uploadcare"]="Uploadcare (Uploads)"
)

echo "| Pattern | Service | Evidence |" >> third-party-services.md
echo "|---------|---------|----------|" >> third-party-services.md

for pattern in "${!JS_PATTERNS[@]}"; do
    # Use extended regex for complex patterns
    match=$(grep -oE "$pattern" all-js-content.txt 2>/dev/null | head -1)
    if [ -n "$match" ]; then
        echo "| $pattern | ${JS_PATTERNS[$pattern]} | Found: $match |" >> third-party-services.md
    fi
done

# Look for exposed API keys/tokens
echo "" >> third-party-services.md
echo "### Potentially Exposed Keys/Tokens" >> third-party-services.md
echo "" >> third-party-services.md

# Common key patterns
declare -A KEY_PATTERNS=(
    ["pk_live_[a-zA-Z0-9]+"]="Stripe Live Public Key"
    ["pk_test_[a-zA-Z0-9]+"]="Stripe Test Public Key"
    ["phc_[a-zA-Z0-9]+"]="PostHog Project Key"
    ["ph_[a-zA-Z0-9]+"]="PostHog Client Key"
    ["AKIA[A-Z0-9]{16}"]="AWS Access Key ID"
    ["[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+"]="Potential JWT"
)

echo "| Pattern | Type | Value (truncated) |" >> third-party-services.md
echo "|---------|------|-------------------|" >> third-party-services.md

for pattern in "${!KEY_PATTERNS[@]}"; do
    matches=$(grep -oE "$pattern" all-js-content.txt 2>/dev/null | head -3)
    for match in $matches; do
        truncated="${match:0:20}..."
        echo "| $pattern | ${KEY_PATTERNS[$pattern]} | $truncated |" >> third-party-services.md
    done
done

# ============================================================
# Summary
# ============================================================
echo "" >> third-party-services.md
echo "## Summary" >> third-party-services.md
echo "" >> third-party-services.md
echo "Services detected across all methods:" >> third-party-services.md
grep -E "^\|.*\|.*\|" third-party-services.md | grep -v "^|--" | grep -v "Pattern" | \
    awk -F'|' '{print $3}' | sort -u | while read service; do
    [ -n "$service" ] && echo "- $service"
done >> third-party-services.md

cat third-party-services.md

echo ""
echo "Full report saved to: $OUTPUT_DIR/third-party-services.md"
