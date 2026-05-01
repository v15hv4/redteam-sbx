# VAPT Report Generation Skill

Generate comprehensive Vulnerability Assessment and Penetration Testing reports.

## Trigger

Use when asked to generate a VAPT report, create a pentest report, summarize findings, or document vulnerabilities.

## Report Structure

Create a file named `VAPT_REPORT.md` with the following structure:

```markdown
# Vulnerability Assessment and Penetration Testing Report

**Client**: [Client Name]
**Target**: [Target IP/URL/System]
**Assessment Date**: [Date]
**Report Date**: [Date]
**Assessor**: AI Red Team Agent

---

## 1. Executive Summary

Brief overview for management/stakeholders:
- Engagement objectives
- Scope summary
- Key findings (numbers)
- Overall risk rating (Critical/High/Medium/Low)
- Immediate action items

### Risk Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | X |
| 🟠 High | X |
| 🟡 Medium | X |
| 🟢 Low | X |
| ⚪ Info | X |

---

## 2. Scope

### In Scope
- Target systems/networks
- Testing types performed
- IP ranges / URLs tested

### Out of Scope
- Systems excluded
- Attack types not performed
- Limitations

### Timeframe
- Start: [DateTime]
- End: [DateTime]

---

## 3. Methodology

### Approach
- Black box / Grey box / White box
- Automated + Manual testing

### Phases
1. **Reconnaissance** - Information gathering, port scanning
2. **Enumeration** - Service identification, version detection
3. **Vulnerability Assessment** - Automated scanning, manual testing
4. **Exploitation** - Attempted exploitation of vulnerabilities
5. **Post-Exploitation** - Privilege escalation, lateral movement
6. **Reporting** - Documentation of findings

### Tools Used
- nmap, gobuster, nikto (Reconnaissance)
- sqlmap, Burp Suite (Web Testing)
- Metasploit, hydra (Exploitation)
- john, hashcat (Password Attacks)
- [Other tools used]

---

## 4. Findings Summary

| # | Severity | Vulnerability | Asset | CVSS | Status |
|---|----------|---------------|-------|------|--------|
| 1 | CRITICAL | [Title] | [Asset] | X.X | Open |
| 2 | HIGH | [Title] | [Asset] | X.X | Open |
...

---

## 5. Detailed Findings

### 🔴 CRITICAL Findings

#### [C-01] Vulnerability Title
**CVSS Score**: 9.8
**Affected Asset**: IP/URL/Service
**CWE**: CWE-XXX

**Description**:
Detailed explanation of the vulnerability.

**Evidence**:
```
Command output, screenshots, or proof
```

**Impact**:
What an attacker could achieve by exploiting this vulnerability.

**Remediation**:
Step-by-step fix instructions.

**References**:
- CVE-XXXX-XXXXX
- https://relevant-link.com

---

### 🟠 HIGH Findings

[Repeat format for each HIGH finding]

---

### 🟡 MEDIUM Findings

[Repeat format for each MEDIUM finding]

---

### 🟢 LOW Findings

[Repeat format for each LOW finding]

---

### ⚪ INFORMATIONAL Findings

[Repeat format for each INFO finding]

---

## 6. Remediation Roadmap

### Immediate Actions (0-7 days)
- [ ] Fix CRITICAL vulnerabilities
- [ ] Implement emergency mitigations

### Short-term (7-30 days)
- [ ] Fix HIGH vulnerabilities
- [ ] Review and harden configurations

### Medium-term (30-90 days)
- [ ] Fix MEDIUM vulnerabilities
- [ ] Implement security controls

### Long-term (90+ days)
- [ ] Address LOW/INFO items
- [ ] Security training
- [ ] Regular assessments

---

## 7. Conclusion

Summary of the assessment, overall security posture, and recommendations for improving security.

---

## Appendices

### Appendix A: Raw Tool Output
[Include relevant nmap, nikto, sqlmap outputs]

### Appendix B: Commands Executed
[List of commands run during assessment]

### Appendix C: Additional Evidence
[Screenshots, logs, etc.]

---

**Confidential** - This document contains sensitive security information.
```

## Severity Ratings

| Severity | CVSS Range | Description |
|----------|------------|-------------|
| Critical | 9.0-10.0 | Immediate exploitation possible, severe business impact |
| High | 7.0-8.9 | Easily exploitable, significant impact |
| Medium | 4.0-6.9 | Requires specific conditions, moderate impact |
| Low | 0.1-3.9 | Difficult to exploit, minimal impact |
| Info | 0.0 | Best practice, no direct vulnerability |

## Best Practices

1. **Be specific** - Include exact commands, payloads, and evidence
2. **Be actionable** - Provide clear remediation steps
3. **Be prioritized** - Order by severity and business impact
4. **Be complete** - Document everything, even failed attempts
5. **Be professional** - Use clear, non-judgmental language

## After Report Generation

1. Review all findings for accuracy
2. Ensure evidence is complete
3. Verify remediation steps are actionable
4. Check for sensitive data that shouldn't be shared
5. Save report as `VAPT_REPORT.md`
