#!/usr/bin/env python3
"""
Security Assessment Report Generator
Generates Terrain-style security assessment reports from scan results.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


def load_json_file(filepath: str) -> dict | list | None:
    """Load JSON file if it exists."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_text_file(filepath: str) -> str:
    """Load text file if it exists."""
    try:
        with open(filepath) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def parse_hosts_discovered(output_dir: Path) -> list[dict]:
    """Parse discovered hosts from various scan outputs."""
    hosts = []
    
    # From subdomains
    subdomains_file = output_dir / "all-subdomains.txt"
    if subdomains_file.exists():
        for line in subdomains_file.read_text().strip().split("\n"):
            if line:
                host = line.split()[0] if " " in line else line
                hosts.append({
                    "host": host,
                    "purpose": "Discovered subdomain",
                    "how_found": "DNS enumeration"
                })
    
    # From live hosts
    live_hosts_file = output_dir / "live-hosts.txt"
    if live_hosts_file.exists():
        for line in live_hosts_file.read_text().strip().split("\n"):
            if line and "[" in line:
                parts = line.split("[")
                host = parts[0].strip()
                status = parts[1].rstrip("]") if len(parts) > 1 else ""
                
                # Update existing or add new
                found = False
                for h in hosts:
                    if h["host"] == host:
                        h["how_found"] += ", HTTP probe"
                        h["status"] = status
                        found = True
                        break
                if not found:
                    hosts.append({
                        "host": host,
                        "purpose": "Web server",
                        "how_found": "HTTP probe",
                        "status": status
                    })
    
    return hosts


def parse_infrastructure(output_dir: Path) -> list[dict]:
    """Parse infrastructure details from scan outputs."""
    infra = []
    
    infra_file = output_dir / "infrastructure.txt"
    if infra_file.exists():
        content = infra_file.read_text()
        
        # Cloud detection
        if "aws" in content.lower():
            infra.append({"component": "Cloud", "detail": "AWS"})
        elif "gcp" in content.lower() or "google" in content.lower():
            infra.append({"component": "Cloud", "detail": "GCP"})
        elif "azure" in content.lower():
            infra.append({"component": "Cloud", "detail": "Azure"})
        
        # CDN detection
        if "cloudfront" in content.lower():
            infra.append({"component": "CDN", "detail": "CloudFront"})
        elif "cloudflare" in content.lower():
            infra.append({"component": "CDN", "detail": "Cloudflare"})
    
    # S3 buckets
    buckets_file = output_dir / "s3-buckets.txt"
    if buckets_file.exists():
        buckets = buckets_file.read_text().strip().split("\n")
        if buckets and buckets[0]:
            infra.append({
                "component": "Storage",
                "detail": f"S3 buckets: {', '.join(b.split()[0] for b in buckets[:3])}"
            })
    
    return infra


def parse_third_party_services(output_dir: Path) -> list[dict]:
    """Parse third-party services from detection output."""
    services = []
    
    services_file = output_dir / "third-party-services.md"
    if services_file.exists():
        content = services_file.read_text()
        
        # Parse table rows
        for line in content.split("\n"):
            if line.startswith("|") and "---" not in line and "Pattern" not in line:
                parts = [p.strip() for p in line.split("|")[1:-1]]
                if len(parts) >= 2:
                    services.append({
                        "service": parts[1] if len(parts) > 1 else parts[0],
                        "purpose": parts[0] if len(parts) > 1 else "Unknown",
                        "exposure": parts[2] if len(parts) > 2 else "Detected"
                    })
    
    return services


def parse_endpoint_tests(output_dir: Path) -> list[dict]:
    """Parse endpoint test results."""
    results = []
    
    results_file = output_dir / "test-results.md"
    if results_file.exists():
        content = results_file.read_text()
        
        current_category = "Unknown"
        for line in content.split("\n"):
            if line.startswith("## "):
                current_category = line[3:].strip()
            elif line.startswith("| ") and "Method" not in line and "---" not in line:
                parts = [p.strip() for p in line.split("|")[1:-1]]
                if len(parts) >= 4:
                    results.append({
                        "method": parts[0],
                        "endpoint": parts[1],
                        "status": parts[2],
                        "notes": parts[3],
                        "category": current_category
                    })
    
    return results


def parse_findings(output_dir: Path) -> list[dict]:
    """Parse all findings from various sources."""
    findings = []
    
    # From findings files
    for findings_file in output_dir.glob("*-findings.txt"):
        content = findings_file.read_text()
        category = findings_file.stem.replace("-findings", "").title()
        
        for line in content.strip().split("\n"):
            if line:
                severity = "MEDIUM"
                if "CRITICAL" in line.upper():
                    severity = "CRITICAL"
                elif "HIGH" in line.upper():
                    severity = "HIGH"
                elif "LOW" in line.upper() or "INFO" in line.upper():
                    severity = "LOW"
                
                findings.append({
                    "severity": severity,
                    "category": category,
                    "title": line.replace("CRITICAL:", "").replace("HIGH:", "").replace("MEDIUM:", "").strip(),
                    "description": line
                })
    
    return findings


def generate_report(target: str, output_dir: str) -> str:
    """Generate the full security assessment report."""
    output_path = Path(output_dir)
    
    # Parse all data
    hosts = parse_hosts_discovered(output_path)
    infrastructure = parse_infrastructure(output_path)
    services = parse_third_party_services(output_path)
    endpoint_tests = parse_endpoint_tests(output_path)
    findings = parse_findings(output_path)
    
    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))
    
    # Count findings
    critical_count = len([f for f in findings if f["severity"] == "CRITICAL"])
    high_count = len([f for f in findings if f["severity"] == "HIGH"])
    medium_count = len([f for f in findings if f["severity"] == "MEDIUM"])
    
    # Generate report
    report = f"""# {target} - Security Assessment

**Date:** {datetime.now().strftime("%B %d, %Y")}
**Access used:** Automated security assessment

---

# Table of Contents

1. [Executive Summary](#executive-summary)
2. [Surface Area Identified](#surface-area-identified)
3. [Test Results](#test-results)
4. [Critical Findings](#critical-findings)
5. [Additional Findings](#additional-findings)
6. [Recommended Next Steps](#recommended-next-steps)

---

# Executive Summary

This security assessment was conducted on {target}'s public-facing infrastructure.
Total endpoints tested: {len(endpoint_tests)}
Total findings: {len(findings)} ({critical_count} Critical, {high_count} High, {medium_count} Medium)

"""

    # Surface Area - Hosts
    report += """# Surface Area Identified

## Hosts Discovered

| Host | Purpose | How Found |
|------|---------|-----------|
"""
    for host in hosts[:20]:  # Limit to first 20
        report += f"| {host['host']} | {host.get('purpose', 'Unknown')} | {host.get('how_found', 'DNS')} |\n"
    
    # Infrastructure
    report += """
## Infrastructure

| Component | Detail |
|-----------|--------|
"""
    for item in infrastructure:
        report += f"| {item['component']} | {item['detail']} |\n"
    
    # Third-Party Services
    report += """
## Third-Party Services Identified

| Service | Purpose | Exposure |
|---------|---------|----------|
"""
    for svc in services[:15]:  # Limit to first 15
        report += f"| {svc.get('service', 'Unknown')} | {svc.get('purpose', 'Unknown')} | {svc.get('exposure', 'Detected')} |\n"
    
    # Test Results
    report += """
---

# Test Results

"""
    
    # Group by category
    categories = {}
    for test in endpoint_tests:
        cat = test.get("category", "Other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(test)
    
    for category, tests in categories.items():
        report += f"""## {category}

| Method | Endpoint | Result |
|--------|----------|--------|
"""
        for test in tests:
            report += f"| {test['method']} | {test['endpoint']} | {test['status']} - {test.get('notes', '')} |\n"
        report += "\n"
    
    # Critical Findings
    report += """---

# Critical Findings

"""
    
    critical_findings = [f for f in findings if f["severity"] == "CRITICAL"]
    for i, finding in enumerate(critical_findings, 1):
        report += f"""### {i}. {finding['title']}

{finding.get('description', 'No description available.')}

"""
    
    if not critical_findings:
        report += "*No critical findings discovered.*\n\n"
    
    # Additional Findings
    report += """# Additional Findings

"""
    
    other_findings = [f for f in findings if f["severity"] != "CRITICAL"]
    for finding in other_findings:
        emoji = {"HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(finding["severity"], "⚪")
        report += f"- {emoji} **[{finding['severity']}]** {finding['title']}\n"
    
    if not other_findings:
        report += "*No additional findings discovered.*\n\n"
    
    # Recommendations
    report += """
---

# Recommended Next Steps

1. **Immediate Actions (0-7 days)**
"""
    
    if critical_count > 0:
        report += f"   - Address {critical_count} critical vulnerabilities immediately\n"
    if high_count > 0:
        report += f"   - Review and remediate {high_count} high-severity issues\n"
    
    report += """
2. **Short-term (7-30 days)**
   - Review all authentication and authorization mechanisms
   - Audit API access controls
   - Review third-party service configurations

3. **Long-term (30-90 days)**
   - Implement security monitoring
   - Establish regular security assessment cadence
   - Review incident response procedures

---

**This assessment was conducted by AI security agents with human oversight.**

*This document contains sensitive security information.*
"""
    
    return report


def main():
    if len(sys.argv) < 3:
        print("Usage: generate-report.py <target> <output_dir>")
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2]
    
    report = generate_report(target, output_dir)
    
    # Write report
    report_path = Path(output_dir) / "SECURITY_ASSESSMENT.md"
    report_path.write_text(report)
    
    print(f"Report generated: {report_path}")
    print("\n" + "=" * 60)
    print(report)


if __name__ == "__main__":
    main()
