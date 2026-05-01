# RedTeam Pi Extension

Autonomous red team penetration testing extension for Pi.

## Architecture: Direct Execution + LLM Analysis

This extension uses a **hybrid architecture** that works with any model:

1. **Security tools execute directly** - nmap, nikto, sqlmap, etc. run via Node.js `execSync`
2. **LLM only analyzes output** - The model receives scan results and provides analysis
3. **No model permission issues** - The model never decides whether to run offensive tools

This means you can use restrictive models like Codex without hitting security refusals.

## Installation

Copy this folder to `.pi/extensions/redteam/` in your project:

```
your-project/
└── .pi/
    └── extensions/
        └── redteam/    ← this folder
```

## Commands

### Full Engagement

| Command | Description |
|---------|-------------|
| `/redteam <domain>` | 🎯 **Terrain-style assessment** - subdomains, infrastructure, services, endpoints, CORS |
| `/redteam-quick <target>` | 🚀 **Quick parallel scan** - nmap, nikto, nuclei, gobuster simultaneously |

### Individual Scans

| Command | Description |
|---------|-------------|
| `/recon <target>` | 🔍 Quick reconnaissance (ports, services, web tech, DNS) |
| `/portscan <target>` | 🔌 Full TCP/UDP port scan |
| `/vulnscan <target>` | 🔎 Vulnerability scanning (nmap scripts, nikto, nuclei) |
| `/webscan <url>` | 🌐 Web directory enumeration and sensitive file check |
| `/sqli <url>` | 💉 SQL injection testing with sqlmap |
| `/bruteforce <target> <service>` | 🔑 Credential brute force (ssh, ftp, http-post) |

### Reconnaissance

| Command | Description |
|---------|-------------|
| `/subdomain <domain>` | 🔍 Subdomain enumeration (subfinder, crt.sh, DNS brute) |
| `/services <domain>` | 🔌 Third-party service detection (DNS, headers, JS) |
| `/cors <api_url>` | 🌐 CORS misconfiguration testing |
| `/endpoints <api_url>` | 🔎 API endpoint discovery with method testing |
| `/tools` | 🔧 Check tool availability and show install commands |

### Reporting

| Command | Description |
|---------|-------------|
| `/finding <severity> <title>` | 📝 Record a vulnerability finding |
| `/report` | 📊 Generate VAPT_REPORT.md |
| `/status` | 📈 Show engagement status |
| `/results [scan_name]` | 📋 Re-display scan results for LLM analysis |

## LLM Tools

The extension provides tools the LLM can call:

| Tool | Description |
|------|-------------|
| `record_finding` | Document a vulnerability with full details |
| `list_findings` | List all recorded findings |
| `run_command` | Execute an additional security command |
| `engagement_info` | Get engagement status |

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    /redteam target.com                  │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              Extension (index.ts)                       │
│                                                         │
│   execSync("nmap -sS -sV target.com")                  │
│   execSync("nikto -h http://target.com")               │
│   execSync("nuclei -u http://target.com")              │
│   execSync("gobuster dir -u http://target.com")        │
│                                                         │
│   (Tools run in parallel, output captured)              │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                      LLM Model                          │
│                                                         │
│   Receives: "Here are the scan results: ..."            │
│   Task: Analyze, identify vulns, call record_finding    │
│                                                         │
│   (Model only does analysis - no execution decisions)   │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    VAPT_REPORT.md                       │
└─────────────────────────────────────────────────────────┘
```

## Example Workflow

```bash
# 1. Run full parallel engagement
/redteam 192.168.1.100

# LLM analyzes results automatically and records findings

# 2. Run additional targeted scans based on LLM recommendations
/sqli "http://192.168.1.100/page.php?id=1"
/bruteforce 192.168.1.100 ssh

# 3. Check status
/status

# 4. Generate report
/report
```

## Required Tools

The extension expects these tools to be installed (standard on Kali Linux):

**Reconnaissance**: nmap, whatweb, dig
**Vulnerability**: nikto, nuclei, sslscan
**Web**: gobuster, dirb, curl
**Exploitation**: sqlmap
**Credentials**: hydra

Install on Debian/Ubuntu/Kali:
```bash
sudo apt install nmap nikto gobuster dirb sqlmap hydra whatweb dnsutils
# nuclei: https://github.com/projectdiscovery/nuclei
```

## Findings Severity

| Level | Emoji | Description |
|-------|-------|-------------|
| Critical | 🔴 | Immediate exploitation possible, severe impact |
| High | 🟠 | Significant risk, should fix soon |
| Medium | 🟡 | Moderate risk, fix in normal cycle |
| Low | 🟢 | Minor issues, low priority |
| Info | ⚪ | Informational, no direct risk |

## File Structure

```
redteam/
├── index.ts              # Extension (direct execution + LLM analysis)
├── package.json          # Manifest
├── README.md             # This file
├── agents/               # (Legacy - not used in direct execution mode)
├── docs/
│   └── PRD.md
└── skills/               # Reference skills for manual testing
    ├── active-directory/
    ├── metasploit/
    ├── password-attacks/
    ├── privilege-escalation/
    ├── reconnaissance/
    ├── vapt-report/
    └── web-exploitation/
```

## Why This Architecture?

**Problem**: Models like Codex refuse to execute offensive security commands.

**Solution**: Don't ask the model to execute anything.
- The extension runs tools directly via `execSync`
- The model only sees output and provides analysis
- No security constraints triggered because the model isn't "hacking" - it's reading logs

This is both more reliable AND faster since tools run in parallel without waiting for LLM round-trips.
