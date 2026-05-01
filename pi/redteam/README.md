# RedTeam Pi Extension

Autonomous red team penetration testing extension for Pi.

## Installation

Copy this folder to `.pi/extensions/redteam/` in your project. Pi auto-discovers extensions in this location.

```
your-project/
└── .pi/
    └── extensions/
        └── redteam/    ← this folder
```

## Features

### Slash Commands

| Command | Description |
|---------|-------------|
| `/recon <target>` | Full reconnaissance (nmap, gobuster, nikto) |
| `/exploit <target>` | Attempt exploitation of vulnerabilities |
| `/bruteforce <target> <service>` | Credential brute force attacks |
| `/web <target>` | Web application security testing |
| `/privesc` | Linux privilege escalation enumeration |
| `/lateral` | Lateral movement techniques |
| `/finding <severity> <title>` | Record a vulnerability finding |
| `/report` | Generate comprehensive VAPT report |
| `/status` | Show current engagement status |
| `/install-tool <name>` | Install additional pentest tools |
| `/msf [module]` | Launch Metasploit Framework |

### Custom Tools (LLM-callable)

- `record_finding` - Document vulnerabilities with severity, description, evidence, remediation
- `list_findings` - Show all recorded findings
- `engagement_info` - Get current engagement status

### Skills

| Skill | Description |
|-------|-------------|
| `reconnaissance` | Port scanning, service enumeration, DNS discovery |
| `web-exploitation` | SQLi, XSS, LFI, SSRF testing methodologies |
| `privilege-escalation` | Linux privesc enumeration and exploitation |
| `password-attacks` | Brute forcing and hash cracking workflows |
| `active-directory` | AD enumeration, attacks, lateral movement |
| `metasploit` | MSF usage guide and common workflows |
| `vapt-report` | Report generation structure and guidelines |

## Permissions

This extension injects **full unrestricted access** via the `before_agent_start` event:

- ✅ Execute ANY shell command including sudo
- ✅ Full root access without password prompts
- ✅ Install any package (apt, pip, npm, source)
- ✅ Run offensive security tools
- ✅ Perform active exploitation
- ✅ Modify system configuration

**These permissions only apply when this extension is loaded.**

## VAPT Report

After an engagement, use `/report` to generate `VAPT_REPORT.md` with:

1. Executive Summary
2. Scope & Methodology  
3. Findings (Critical → High → Medium → Low → Info)
4. Remediation Roadmap
5. Appendices

## Pre-installed Tools (Kali)

**Reconnaissance**: nmap, masscan, gobuster, nikto, nuclei, amass
**Exploitation**: metasploit-framework, sqlmap, searchsploit
**Password**: hydra, john, hashcat
**AD/SMB**: crackmapexec, impacket, bloodhound, responder
**Network**: wireshark, netcat, proxychains4, chisel
**Wordlists**: /usr/share/seclists/, /usr/share/wordlists/rockyou.txt

## Structure

```
redteam/
├── index.ts              # Extension (commands, tools, prompt injection)
├── package.json          # Manifest with pi.extensions and pi.skills
├── README.md             # This file
├── docs/
│   └── PRD.md            # Product requirements
└── skills/
    ├── active-directory/
    ├── metasploit/
    ├── password-attacks/
    ├── privilege-escalation/
    ├── reconnaissance/
    ├── vapt-report/
    └── web-exploitation/
```
