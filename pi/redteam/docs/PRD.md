# RedTeam Pi Extension - PRD

## Overview

A Pi extension that transforms the coding agent into an autonomous red team operator. The agent runs inside a Kali Linux sandbox environment with full system privileges and can execute any command, install any tool, and perform comprehensive penetration testing.

## Environment

- **OS**: Kali Linux Rolling (via Vagrant)
- **Resources**: 8GB RAM, 4 CPUs
- **Privileges**: Full sudo access, unrestricted command execution
- **Network**: Private isolated network for safe testing

## Pre-installed Tools

- **Reconnaissance**: nmap, gobuster, dirb, nikto
- **Exploitation**: metasploit-framework, sqlmap, hydra
- **Password Attacks**: john, hashcat
- **Web Testing**: burpsuite, nikto
- **Network**: wireshark, netcat-traditional, proxychains4
- **Wordlists**: seclists, wordlists

## Slash Commands

### /recon <target>
Perform reconnaissance on a target. Includes:
- Port scanning (nmap)
- Service enumeration
- DNS enumeration
- Web directory discovery

### /exploit <target> [service]
Attempt exploitation against discovered vulnerabilities:
- Automated vulnerability scanning
- Metasploit integration
- SQLi testing
- Known CVE exploitation

### /bruteforce <target> <service>
Credential attacks:
- SSH/FTP/HTTP brute forcing (hydra)
- Hash cracking (john/hashcat)

### /web <target>
Web application testing:
- Directory enumeration (gobuster/dirb)
- Vulnerability scanning (nikto)
- SQL injection testing (sqlmap)
- XSS detection

### /report
Generate a comprehensive VAPT report of all findings ordered by severity.

## Output

At the end of every engagement, generate a VAPT report containing:
1. Executive Summary
2. Scope & Methodology
3. Findings (ordered by severity: Critical > High > Medium > Low > Info)
4. Detailed Vulnerability Descriptions
5. Remediation Recommendations
6. Appendices (raw tool output, screenshots)

## Permissions

The extension injects full unrestricted access via `before_agent_start`:
- Execute any shell command
- Use sudo without restrictions
- Install/configure any package
- Modify system files
- Run any pentest tool
