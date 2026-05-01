# Reconnaissance Skill

Comprehensive target reconnaissance and enumeration.

## Trigger

Use when asked to perform reconnaissance, enumerate a target, discover services, or map an attack surface.

## Workflow

### Phase 1: Passive Reconnaissance
1. **OSINT** - Gather public information about the target
2. **DNS enumeration** - Discover subdomains, DNS records
3. **WHOIS lookup** - Registration information

### Phase 2: Active Scanning
1. **Port scanning** with nmap:
   ```bash
   # Fast initial scan
   nmap -sS -T4 --top-ports 1000 -oN initial_scan.txt TARGET
   
   # Full TCP scan
   nmap -sS -sV -O -A -p- -oN full_tcp.txt TARGET
   
   # UDP scan (top ports)
   nmap -sU --top-ports 100 -oN udp_scan.txt TARGET
   ```

2. **Service version detection**:
   ```bash
   nmap -sV --version-intensity 5 -p PORTS TARGET
   ```

3. **Script scanning**:
   ```bash
   nmap -sC -sV -p PORTS TARGET
   nmap --script vuln -p PORTS TARGET
   ```

### Phase 3: Web Enumeration (if web services found)
1. **Directory discovery**:
   ```bash
   gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt,bak -o dirs.txt
   ```

2. **Vulnerability scanning**:
   ```bash
   nikto -h http://TARGET -o nikto.txt
   ```

3. **Technology fingerprinting**:
   ```bash
   whatweb http://TARGET
   ```

### Phase 4: Documentation
- Record all open ports and services
- Note software versions (potential CVEs)
- Document the attack surface
- Use `record_finding` for any immediate vulnerabilities discovered

## Tools
- nmap
- gobuster
- dirb
- nikto
- whatweb
- dnsrecon
- dig
- whois

## Output
Provide a structured summary:
1. Open ports and services
2. Identified software versions
3. Potential attack vectors
4. Immediate vulnerabilities found
