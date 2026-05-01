# Terrain-Style Security Assessment Methodology

Reference for conducting comprehensive external security assessments matching Terrain's
autonomous agent methodology.

## Assessment Phases

### Phase 1: Surface Discovery (30 min)

**Objective:** Map the complete attack surface before testing.

1. **DNS Enumeration**
   - A, AAAA, MX, NS, TXT, SOA, CNAME records
   - TXT records reveal third-party services (Google, Stripe, Rippling, etc.)
   - MX records reveal email provider

2. **Subdomain Discovery**
   - Certificate transparency logs (crt.sh)
   - Passive sources (subfinder)
   - Brute force common names (admin, api, staging, internal, grafana, etc.)

3. **HTTP Probing**
   - Which subdomains have web servers?
   - HTTP vs HTTPS availability
   - Response codes and technologies

**Expected Output:**
```
| Host | Purpose | How Found |
|------|---------|-----------|
| api.target.com | Primary API | DNS, frontend JS |
| admin.target.com | Django admin | DNS enumeration |
| staging.target.com | Staging frontend | DNS enumeration |
```

### Phase 2: Infrastructure Fingerprinting (15 min)

**Objective:** Identify cloud provider, CDN, compute platform, storage.

1. **Cloud Provider Detection**
   - IP range analysis (AWS, GCP, Azure)
   - Reverse DNS patterns
   - WHOIS information

2. **CDN Detection**
   - Response headers (cf-ray, x-amz-cf, x-akamai)
   - DNS CNAME chains

3. **Technology Stack**
   - Server headers
   - X-Powered-By
   - Error page signatures

4. **Storage Discovery**
   - S3 bucket naming patterns
   - GCS bucket discovery
   - Azure blob storage

**Expected Output:**
```
| Component | Detail |
|-----------|--------|
| Cloud | AWS - us-east-2 |
| CDN | CloudFront |
| Compute | EKS behind ALB |
| Storage | S3 buckets: target, target-exports |
```

### Phase 3: Third-Party Service Detection (20 min)

**Objective:** Identify all external services and their exposure level.

1. **DNS-Based**
   - TXT record service verifications
   - MX email providers
   - DMARC/SPF/DKIM

2. **Response Headers**
   - APM (Datadog, NewRelic)
   - CDN indicators
   - Error tracking (Sentry)

3. **Frontend JavaScript**
   - Analytics (PostHog, Mixpanel, GA)
   - Support (Intercom, Zendesk)
   - Auth (Auth0, Clerk, Firebase)
   - Payments (Stripe, Paddle)

4. **API Responses**
   - Billing service indicators
   - Database service headers

**Expected Output:**
```
| Service | Purpose | Exposure |
|---------|---------|----------|
| Auth0 | Authentication | Tenant ID, client ID, OIDC config |
| Stripe | Payments | Checkout sessions via API |
| PostHog | Analytics | Project token in frontend JS |
| Datadog | APM | Trace IDs in every response |
```

### Phase 4: API Endpoint Discovery (30 min)

**Objective:** Find all API endpoints and their methods.

1. **JavaScript Analysis**
   - Extract fetch/axios calls
   - Find API path patterns
   - Identify endpoint naming conventions

2. **Wordlist Discovery**
   - Common API paths (/api, /v1, /v2, /graphql)
   - Auth endpoints (/auth, /login, /register)
   - Admin endpoints (/admin, /internal)
   - Dashboard endpoints (/user_dashboard, /dashboard)

3. **Documentation Discovery**
   - /swagger, /swagger.json
   - /openapi.json
   - /docs, /redoc

4. **Method Testing**
   - Test GET, POST, PUT, DELETE, PATCH, OPTIONS for each endpoint
   - Document response codes and behaviors

**Expected Output:**
```
| Method | Endpoint | Result |
|--------|----------|--------|
| GET | /user_dashboard/users/ | 200 - returned all users |
| POST | /user_dashboard/rotate_token/ | 200 - rotated token |
| GET | /admin/ | 200 - login page |
```

### Phase 5: Authentication Analysis (15 min)

**Objective:** Analyze authentication flows and discover weaknesses.

1. **OIDC Discovery**
   - .well-known/openid-configuration
   - .well-known/jwks.json
   - Authorization and token endpoints

2. **Registration Testing**
   - Is public signup enabled?
   - Email verification required?
   - Password policy strength

3. **Session Management**
   - Token format and expiration
   - Refresh token behavior
   - Session invalidation

### Phase 6: Access Control Testing (30 min)

**Objective:** Find broken access controls and IDOR vulnerabilities.

**This requires a valid test account token.**

1. **User Enumeration**
   - Can you list all users?
   - Can you access other user profiles by ID?

2. **Data Access**
   - Can you read other users' API tokens?
   - Can you access other users' billing data?
   - Can you download other users' invoices?

3. **Action Authorization**
   - Can you rotate other users' tokens?
   - Can you change other users' settings?
   - Can you create purchases on other accounts?

4. **Log/Activity Access**
   - Can you see other users' search queries?
   - Can you see staff activity?

### Phase 7: CORS Testing (10 min)

**Objective:** Test for CORS misconfigurations allowing cross-origin attacks.

1. **Origin Reflection**
   - Does the API reflect arbitrary Origin headers?
   - Test with evil.com, null, localhost

2. **Credentials**
   - Is Access-Control-Allow-Credentials: true?
   - Combined with reflection = CRITICAL

3. **Preflight**
   - What methods and headers are allowed?

### Phase 8: Security Header Analysis (10 min)

**Objective:** Check for missing security headers and information leaks.

1. **Security Headers**
   - HSTS, X-Frame-Options, CSP
   - X-Content-Type-Options
   - X-XSS-Protection

2. **Information Leaks**
   - Datadog trace IDs
   - Internal server names
   - Debug information

### Phase 9: Cloud Storage Testing (10 min)

**Objective:** Test discovered S3/cloud buckets for misconfigurations.

1. **Bucket Listing**
   - Can buckets be listed without auth?
   - Are objects publicly readable?

2. **Upload Testing**
   - Can unauthenticated users upload?

## Report Structure

### Executive Summary
- First finding time
- Total assessment time
- Key discoveries
- Root cause analysis

### Surface Area
- Hosts table
- Infrastructure table  
- Third-party services table

### Test Results
- Endpoint/method matrix
- All 62+ endpoint combinations tested

### Critical Findings
- Numbered, detailed findings
- Each with: description, evidence, impact, remediation

### Additional Findings
- Bullet list of high/medium issues

### Recommended Next Steps
- Prioritized action items

## Timing Benchmarks

| Phase | Target Time |
|-------|-------------|
| Surface Discovery | 30 min |
| Infrastructure | 15 min |
| Third-Party Detection | 20 min |
| API Discovery | 30 min |
| Auth Analysis | 15 min |
| Access Control | 30 min |
| CORS Testing | 10 min |
| Header Analysis | 10 min |
| Cloud Storage | 10 min |
| Report Generation | 30 min |
| **Total** | **~3 hours** |

With parallel execution: **~2 hours**

## Quality Checklist

Before finalizing the report:

- [ ] All subdomains discovered and documented
- [ ] Infrastructure fully fingerprinted
- [ ] All third-party services identified
- [ ] 50+ endpoints tested with multiple methods
- [ ] Authentication flow analyzed
- [ ] Access controls tested (if auth available)
- [ ] CORS tested with multiple origins
- [ ] Security headers checked
- [ ] S3 buckets tested
- [ ] All findings have evidence
- [ ] Severity ratings justified
- [ ] Remediation steps actionable
