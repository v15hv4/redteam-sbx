# Privilege Escalation Skill

Linux privilege escalation enumeration and exploitation.

## Trigger

Use when you have initial access to a system and need to escalate privileges to root.

## Workflow

### Phase 1: System Enumeration

1. **Basic system info**:
   ```bash
   uname -a
   cat /etc/*release*
   hostname
   id
   whoami
   ```

2. **User enumeration**:
   ```bash
   cat /etc/passwd
   cat /etc/shadow 2>/dev/null
   cat /etc/group
   ls -la /home/
   ```

3. **Network info**:
   ```bash
   ip a
   netstat -tulpn
   ss -tulpn
   cat /etc/hosts
   ```

### Phase 2: Automated Enumeration

1. **LinPEAS** (comprehensive):
   ```bash
   curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
   chmod +x linpeas.sh
   ./linpeas.sh | tee linpeas_output.txt
   ```

2. **Linux Exploit Suggester**:
   ```bash
   curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -o les.sh
   chmod +x les.sh
   ./les.sh
   ```

### Phase 3: Common Privilege Escalation Vectors

#### SUID Binaries
```bash
find / -perm -4000 2>/dev/null
find / -perm -2000 2>/dev/null
# Check GTFOBins for exploitation: https://gtfobins.github.io/
```

#### Sudo Permissions
```bash
sudo -l
# Check for NOPASSWD entries
# Check for vulnerable sudo versions (CVE-2021-3156)
```

#### Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
# Look for writable scripts run by root
```

#### Writable Files/Directories
```bash
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null
# Check /etc/passwd (can you add a user?)
# Check PATH for writable directories
```

#### Capabilities
```bash
getcap -r / 2>/dev/null
# Look for cap_setuid, cap_setgid
```

#### Kernel Exploits
```bash
uname -r
# Search for exploits:
# - DirtyPipe (CVE-2022-0847) - Linux 5.8+
# - DirtyCow (CVE-2016-5195) - Linux < 4.8.3
# - PwnKit (CVE-2021-4034) - polkit
```

#### Sensitive Files
```bash
cat ~/.bash_history
cat ~/.mysql_history
find / -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "id_rsa" 2>/dev/null
find / -name ".git-credentials" 2>/dev/null
```

### Phase 4: Exploitation

Based on enumeration, exploit the most promising vector:

1. **SUID binary abuse** - Use GTFOBins techniques
2. **Sudo misconfiguration** - Escape to shell
3. **Cron job hijacking** - Replace script or abuse PATH
4. **Kernel exploit** - Compile and run
5. **Credential reuse** - Found passwords may work for root

### Phase 5: Post-Exploitation

After gaining root:
```bash
id
whoami
cat /root/flag.txt
cat /etc/shadow
```

## Tools
- LinPEAS
- Linux Exploit Suggester
- GTFOBins reference
- pspy (process monitoring)

## Record Findings

Use `record_finding` for:
- Each privilege escalation vector found
- Successfully exploited vulnerabilities
- Misconfigurations discovered
